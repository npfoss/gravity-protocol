
const IPFS = require('ipfs');
const Cookies = require('js-cookie');
const sodium = require('libsodium-wrappers');


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

const writeFile = async (ipfs, path, data) =>
  // TODO: might need to use locks when writing?
  ipfs.files.write(path,
    Buffer.from(data),
    { parents: true, create: true, truncate: true });


//*  the protocol
class GravityProtocol {
  constructor() {
    let ipfsReady = false;
    let sodiumReady = false;
    this.ready = () => ipfsReady && sodiumReady;
    this.readyAsync = async () => {
      await sodium.ready;
      while (!ipfsReady) {
        await sleep(400);
      }
      return true;
    };

    const node = new IPFS();
    node.on('ready', () => {
      // Ready to use!
      // See https://github.com/ipfs/js-ipfs#core-api

      ipfsReady = true;
    });

    (async function awaitSodiumReady() {
      await sodium.ready;
      sodiumReady = true;
    }());

    this.loadDirs = async (path) => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      return loadDirs(node, path);
    };

    // use with caution
    this.setMasterKey = (newkey) => {
      Cookies.set('gravity-master-key', newkey);// , { secure: true }); // for https only
      // TODO: store somewhere better than in a cookie.
      //  (only store a device key, keep master key enc in profile only)
    };

    // use with caution
    this.resetMasterKey = () => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      const key = sodium.crypto_secretbox_keygen();
      this.setMasterKey(sodium.to_base64(key));
    };

    this.getMasterKey = () => {
      const cookie = Cookies.get('gravity-master-key');
      if (cookie === undefined) {
        throw new Error('No master key');
      }
      return sodium.from_base64(cookie);
    };

    this.encrypt = (key, message) => {
      // also prepends nonce
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      return uintConcat(nonce, sodium.crypto_secretbox_easy(message, nonce, key));
    };

    this.decrypt = (key, nonceAndCiphertext) => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
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
      await this.readyAsync();
      return node.id();
    };

    this.getContacts = async () => {
      await this.readyAsync();

      const mkey = this.getMasterKey();
      return readFile(node, '/private/contacts.json.enc')
        .then(contacts => JSON.parse(this.decrypt(mkey, contacts)))
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
      await this.readyAsync();
      const publicKey = base64toURL(publicKey_);

      const contacts = await this.getContacts();
      let mySecret;
      let nonce;
      let rewrite = false;
      const promisesToWaitFor = [];

      if (!(publicKey in contacts)) {
        contacts[publicKey] = [];
      }

      if ('my-secret' in contacts[publicKey]) {
        // 'my-secret' as opposed to 'their-secret', which is in their profile for me
        //  these are the symmetric keys used for everything between me and them
        mySecret = sodium.from_base64(contacts[publicKey]['my-secret']);
      } else {
        rewrite = true;
        mySecret = sodium.crypto_secretbox_keygen();
        contacts[publicKey]['my-secret'] = sodium.to_base64(mySecret);
      }

      if ('my-secret-nonce' in contacts[publicKey]) {
        nonce = sodium.from_base64(contacts[publicKey]['my-secret-nonce']);
      } else {
        rewrite = true;
        nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      }

      if (rewrite) {
        // const encContacts =
        // promisesToWaitFor.push(writeFile(node, '/private/contacts.json.enc', JSON.stringify(encContacts)));
      }

      const message = `Hello ${publicKey} ${sodium.to_base64(mySecret)} ${sodium.to_base64(nonce)}`;
      console.log(message);

      // have to encrypt the thing regardless to check if it's already there
      const ciphertext = sodium.crypto_box_seal();

      // actually don't even need to check because we'd be replacing it with the same thing...


      return mySecret;
    };
  }
}


module.exports = GravityProtocol;
