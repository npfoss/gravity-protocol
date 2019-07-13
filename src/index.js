
const IPFS = require('ipfs');
const Cookies = require('js-cookie');
const sodium = require('libsodium-wrappers');
const multihashing = require('multihashing');
const libp2pcrypto = require('libp2p-crypto');
const NodeRSA = require('node-rsa');


//*  UTILS

const FILE_TYPES = {
  FILE: 0,
  DIRECTORY: 1,
};
// source: https://github.com/ipfs/js-ipfs/blob/master/examples/browser-mfs/filetree.js
const loadDirs = async function (ipfs, path) {
  const output = {};
  const cleanpath = path.replace(/\/\/+/g, '/');

  const contents = await ipfs.files.ls(cleanpath, {
    long: true,
  });
  // .catch(error => console.error(error));

  for (let i = 0; i < contents.length; i += 1) {
    const entry = contents[i];
    output[entry.name] = entry;

    if (entry.type === FILE_TYPES.DIRECTORY) {
      entry.contents = await loadDirs(ipfs, `${cleanpath}/${entry.name}`);
    }
  }

  return output;
};

// concatenates two Uint8Array objects
const uintConcat = (a, b) => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
};

// sleep nonblocking
const sleep = ms => new Promise(r => setTimeout(r, ms));

// for base64 string conversion to/from url safe strings (for pubkeys)
// copies the format used by libsodium
const toURL64replacements = { '+': '-', '/': '_', '=': '' };
const fromURL64replacements = { '-': '+', _: '/' };
const base64toURL = s => s.replace(/[+/=]+/g, c => toURL64replacements[c]);
const URLtoBase64 = s => `${s.replace(/[._-]+/g, c => fromURL64replacements[c])}=`;

// read/write file from MFS. making it a util so it's abstracted away and be changed later
// returns promise
const readFile = (ipfs, path) => ipfs.files.read(path);

const writeFile = async (ipfs, path, data) => {
  // TODO: might need to use locks when writing?
  ipfs.files.write(path, Buffer.from(data), { parents: true, create: true, truncate: true });
};

// use standard format for public keys
/* supports:
    * IPFS protobuf-encoded 2048 bit RSA key --> pkcs8 pem
*/
const toStandardPublicKeyFormat = (publicKey) => {
  if (publicKey.length === 400) {
    // probably an IPFS protobuf-encoded 2048 bit RSA key

    const buf = Buffer.from(publicKey, 'base64');
    // eslint-disable-next-line no-underscore-dangle
    const tempPub = libp2pcrypto.keys.unmarshalPublicKey(buf)._key;

    const key = new NodeRSA();
    key.importKey({
      n: Buffer.from(tempPub.n, 'base64'),
      e: Buffer.from(tempPub.e, 'base64'),
    }, 'components-public');

    return key.exportKey('pkcs8-public-pem');
  }
  throw new Error('Unrecognized public key type');
};
// encrypt things with public keys
// returns ciphertext as buffer
// supports: RSA,
const encAsymm = async (publicKey, message) => {
  const key = new NodeRSA();
  key.importKey(publicKey);
  return key.encrypt(message);
};

// decrypt with ipfs node's private key
// returns decrypted stuff as buffer
// supports RSA,
const decAsymm = async (ipfs, ciphertext) => {
  // eslint-disable-next-line no-underscore-dangle
  const privateKey = ipfs._peerInfo.id._privKey._key;

  const privkey = new NodeRSA();
  privkey.importKey({
    n: Buffer.from(privateKey.n, 'base64'),
    e: Buffer.from(privateKey.e, 'base64'),
    d: Buffer.from(privateKey.d, 'base64'),
    p: Buffer.from(privateKey.p, 'base64'),
    q: Buffer.from(privateKey.q, 'base64'),
    dmp1: Buffer.from(privateKey.dp, 'base64'),
    dmq1: Buffer.from(privateKey.dq, 'base64'),
    coeff: Buffer.from(privateKey.qi, 'base64'),
  }, 'components');

  return privkey.decrypt(ciphertext);
};


//*  the protocol
class GravityProtocol {
  constructor() {
    let ipfsReadyFlag = false;
    this.ipfsReady = async () => {
      while (!ipfsReadyFlag) {
        await sleep(400);
      }
      return true;
    };
    this.sodiumReady = async () => sodium.ready;

    const node = new IPFS();
    node.on('ready', () => {
      // Ready to use!
      // See https://github.com/ipfs/js-ipfs#core-api

      ipfsReadyFlag = true;

      // node.files.rm('/private', { recursive: true });
    });

    this.loadDirs = async (path) => {
      await this.ipfsReady();

      return loadDirs(node, path);
    };

    // use with caution
    this.setMasterKey = (newkey) => {
      Cookies.set('gravity-master-key', newkey);// , { secure: true }); // for https only
      // TODO: store somewhere better than in a cookie.
      //  (only store a device key, keep master key enc in profile only)
    };

    // use with caution
    this.resetMasterKey = async () => {
      await this.sodiumReady();

      const key = sodium.crypto_secretbox_keygen();
      this.setMasterKey(sodium.to_base64(key));
      return key;
    };

    this.getMasterKey = async () => {
      await this.sodiumReady();

      const cookie = Cookies.get('gravity-master-key');
      if (cookie === undefined) {
        throw new Error('No master key');
      }
      return sodium.from_base64(cookie);
    };

    this.encrypt = async (key, message) => {
      // also prepends nonce
      await this.sodiumReady();

      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      return uintConcat(nonce, sodium.crypto_secretbox_easy(message, nonce, key));
    };

    this.decrypt = async (key, nonceAndCiphertext) => {
      await this.sodiumReady();

      if (nonceAndCiphertext.length
          < sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES) {
        throw new Error('Short message');
      }
      const nonce = nonceAndCiphertext.slice(0, sodium.crypto_secretbox_NONCEBYTES);
      const ciphertext = nonceAndCiphertext.slice(sodium.crypto_secretbox_NONCEBYTES);
      const m = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
      return sodium.to_string(m);
    };

    this.getNodeInfo = async () => {
      await this.ipfsReady();
      return node.id();
    };

    // returns the top level profile hash, the one that should be publicized in the DHT
    this.getProfileHash = async () => {
      await this.ipfsReady();

      return (await node.files.stat('/')).hash;
    }

    this.getContacts = async () => {
      await this.ipfsReady();

      const mkey = await this.getMasterKey();
      return readFile(node, '/private/contacts.json.enc')
        .then(async contacts => JSON.parse(await this.decrypt(mkey, contacts)))
        .catch((err) => {
          console.log("got this error but we're handling it:");
          console.log(err);
          return {};
        });
    };

    // checks if already in contacts
    // adds a file in the subscribers folder for this friend so they can find the shared secret
    // adds them as contact (record shared secret, etc)
    this.addSubscriber = async (publicKey_) => {
      await this.ipfsReady();
      await this.sodiumReady();

      /* note: choosing to do everything with their true public key in a standard format
       *  because if we were to use the short IPFS ones (Qm...8g) it would change every time their
       *  protobuf format changed (i.e. they add support for another key type)
       */
      const publicKey = toStandardPublicKeyFormat(publicKey_);

      const contacts = await this.getContacts();
      let mySecret;
      const promisesToWaitFor = [];

      if (!(publicKey in contacts)) {
        contacts[publicKey] = {};
      }

      if ('my-secret' in contacts[publicKey]) {
        // 'my-secret' as opposed to 'their-secret', which is in their profile for me
        //  these are the symmetric keys used for everything between me and them
        mySecret = sodium.from_base64(contacts[publicKey]['my-secret']);
      } else {
        mySecret = sodium.crypto_secretbox_keygen();
        contacts[publicKey]['my-secret'] = sodium.to_base64(mySecret);

        // also save it for important future use
        const encContacts = await this.encrypt(await this.getMasterKey(), JSON.stringify(contacts));
        promisesToWaitFor.push(writeFile(node, '/private/contacts.json.enc', encContacts));
      }

      const message = `Hello ${publicKey} : ${sodium.to_base64(mySecret)}`;
      const ciphertext = await encAsymm(publicKey, message);
      const hash = multihashing.multihash.toB58String(multihashing(message, 'sha2-256'));

      // just write it regardless;
      //  if it's already there we'll have used the same secret and same name anyways
      promisesToWaitFor.push(writeFile(node, `/subscribers/${hash}`, ciphertext));

      await Promise.all(promisesToWaitFor);
      return mySecret;
    };
  }
}


module.exports = GravityProtocol;
