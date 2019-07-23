
const IPFS = require('ipfs');
const Cookies = require('js-cookie');
const sodium = require('libsodium-wrappers');
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
      // TODO: don't await in loop! use promises better, or something
      // eslint-disable-next-line no-await-in-loop
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
/* eslint-disable */
// RE-ENABLE ONCE THEY'RE USED
const toURL64replacements = { '+': '-', '/': '_', '=': '' };
const fromURL64replacements = { '-': '+', _: '/' };
const base64toURL = s => s.replace(/[+/=]+/g, c => toURL64replacements[c]);
const URLtoBase64 = s => `${s.replace(/[._-]+/g, c => fromURL64replacements[c])}=`;
/* eslint-enable */

// read/write file from MFS. making it a util so it's abstracted away and be changed later
// returns promise
const readFile = (ipfs, path) => ipfs.files.read(path);

// TODO: might need to use locks
const writeFile = (ipfs, path, data) => // eslint-disable-next-line implicit-arrow-linebreak
  ipfs.files.write(path, Buffer.from(data), { parents: true, create: true, truncate: true });

// for convenience and clarity since this gets used a lot
// returns base64 string
/*
based on this calculation:
sqrt[2*2^(80)*10^(-12)] = 1.5 million
with 80 bits (14 chars in base64) you can have about 1.5 mil groups/subscribers in your profile
  without the probability of collision exceeding one in a trillion
*/
const hashfunc = message => sodium.to_base64(sodium.crypto_generichash(10, Buffer.from(message)));

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
const decAsymm = async (privateKey, ciphertext) => {
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

// returns the one successful promise from a list, or rejects with list of errors
// copied from: https://stackoverflow.com/a/37235274/7343159
/* eslint-disable arrow-body-style */
const returnSuccessful = (promises) => {
  return Promise.all(promises.map((p) => {
    // If a request fails, count that as a resolution so it will keep
    // waiting for other possible successes. If a request succeeds,
    // treat it as a rejection so Promise.all immediately bails out.
    return p.then(
      val => Promise.reject(val),
      err => Promise.resolve(err),
    );
  })).then(
    // If '.all' resolved, we've just got an array of errors.
    errors => Promise.reject(errors),
    // If '.all' rejected, we've got the result we wanted.
    val => Promise.resolve(val),
  );
};
/* eslint-enable arrow-body-style */

// UUID generator, taken from
//  https://stackoverflow.com/questions/105034/create-guid-uuid-in-javascript/2117523#2117523
/* eslint-disable */
function uuidv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  )
}
/* eslint-enable */


//*  the protocol
class GravityProtocol {
  constructor() {
    let ipfsReadyFlag = false;
    this.ipfsReady = async () => {
      while (!ipfsReadyFlag) {
        // eslint-disable-next-line no-await-in-loop
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

      // node.files.rm('/posts', { recursive: true }).catch(() => {});
    });


    // use standard format for public keys
    /* supports:
        * pkcs8 pem encoded key (standard for RSA) --> pkcs8 pem
        * IPFS protobuf-encoded 2048 bit RSA key --> pkcs8 pem
    */
    // TODO: SUPPORT ED25519! the bug was figured out: https://github.com/ipfs/js-ipfs/issues/2261
    this.toStandardPublicKeyFormat = (publicKey) => {
      // already correctly formatted pkcs8-pem RSA key
      try {
        const key = new NodeRSA(publicKey, 'pkcs8-public-pem');
        return key.exportKey('pkcs8-public-pem');
      } catch (err) {
        // console.log('not an RSA pem')
      }
      // ipfs protobuf-encoded RSA public key
      try {
        const buf = Buffer.from(publicKey, 'base64');
        // eslint-disable-next-line no-underscore-dangle
        const tempPub = libp2pcrypto.keys.unmarshalPublicKey(buf)._key;

        const key = new NodeRSA();
        key.importKey({
          n: Buffer.from(tempPub.n, 'base64'),
          e: Buffer.from(tempPub.e, 'base64'),
        }, 'components-public');

        return key.exportKey('pkcs8-public-pem');
      } catch (err) {
        // console.log('not IPFS protobuf RSA')
      }

      throw new Error('Unrecognized public key type');
    };

    this.getNodeInfo = async () => {
      await this.ipfsReady();
      return node.id();
    };

    // returns this instance's public key
    this.getPublicKey = async () => {
      const info = await this.getNodeInfo();
      return this.toStandardPublicKeyFormat(info.publicKey);
    };

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

    // returns the top level profile hash, the one that should be publicized in the DHT
    this.getMyProfileHash = async () => {
      await this.ipfsReady();

      return (await node.files.stat('/')).hash;
    };

    this.getContacts = async () => {
      await this.ipfsReady();

      const mkey = await this.getMasterKey();
      return readFile(node, '/private/contacts.json.enc')
        .then(async contacts => JSON.parse(await this.decrypt(mkey, contacts)))
        .catch((err) => {
          if (err.message.includes('exist')) {
            console.log("got this error in getContacts but we're handling it:");
            console.log(err);
            return {};
          }
          throw err;
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
      const publicKey = this.toStandardPublicKeyFormat(publicKey_);

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
      const hash = hashfunc(message);

      // just write it regardless;
      //  if it's already there we'll have used the same secret and same name anyways
      promisesToWaitFor.push(writeFile(node, `/subscribers/${hash}`, ciphertext));

      await Promise.all(promisesToWaitFor);
      return mySecret;
    };

    // given the path to the subscribers folder of someone else's profile,
    // try to decrypt each blob in order to find the one intended for you
    // returns the shared secret as buffer/Uint8Array
    this.testDecryptAllSubscribers = async (path) => {
      // TODO: check if the one you remember (from contacts) is still there first,
      //    in a function that would otherwise call this
      await this.ipfsReady();
      await this.sodiumReady();

      // eslint-disable-next-line no-underscore-dangle
      const privateKey = node._peerInfo.id._privKey._key;

      const lst = await node.ls(path);

      const promises = lst.map(async (obj) => {
        const ciphertext = await node.cat(obj.hash);

        // RSA lib will err if key is wrong. this is good. it gets trapped in the promise correctly
        const res = (await decAsymm(privateKey, ciphertext)).toString();

        if (res.slice(0, 5) !== 'Hello') {
          throw new Error('Decrypted message not in the correct format');
        }

        return res.split(': ').pop();
      });

      return sodium.from_base64(await returnSuccessful(promises));
    };

    // TODO: should query IPNS (DHT). hardcoded for now to unblock other stuff
    // returns the most recent top level hash of the profile associated with the given public key
    // ^^ well, it's supposed to. doesn't yet. TODO
    this.lookupProfileHash = async (publicKey) => {
      console.warn(`not actually looking anything up for ${publicKey}`);
      return 'QmRMtCEBe3t6nFfr4Ne9pqmQo4eVweuh9hv8NSoA59579m';
      // still unfinished. actually expects `publicKey` to be the node ID
      // await this.ipfsReady();
      // console.log(`looking up: /ipns/${publicKey}`);
      // return node.name.resolve(`/ipns/${publicKey}`, {
      //   nocache: false,
      // });
    };

    // returns the group key for the given group
    // no 'this' because I'm trying to make it harder to accidentally mishandle keys
    const getGroupKey = async (groupSalt) => {
      await this.sodiumReady();
      await this.ipfsReady();

      const masterKey = await this.getMasterKey();
      const groupKeyBuf = await this.decrypt(masterKey, await readFile(node, `/groups/${groupSalt}/me`));
      return sodium.from_base64(JSON.parse(groupKeyBuf.toString())[0]);
    };

    // returns the info JSON for the given group
    this.getGroupInfo = async (groupSalt) => {
      await this.ipfsReady();

      const groupKey = await getGroupKey(groupSalt);
      let enc;
      try {
        enc = await readFile(node, `/groups/${groupSalt}/info.json.enc`);
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('Got this error in getGroupInfo but it probably just means there was no group info:');
          console.log(err);
          return {};
        }
        throw err;
      }
      return JSON.parse(await this.decrypt(groupKey, enc));
    };

    // takes an object mapping public keys to nicknames (so you can do many at once)
    // sets the nicknames for those people in the group corresponding to groupSalt
    this.setNicknames = async (publicKeyToName, groupSalt) => {
      await this.ipfsReady();
      await this.sodiumReady();

      // first make sure everyone is in the group
      const contacts = await this.getContacts();
      const filenames = await node.files.ls(`/groups/${groupSalt}`)
        .then(flist => flist.map(f => f.name));
      const groupKey = await getGroupKey(groupSalt);

      const myPublicKey = await this.getPublicKey();
      const missing = Object.keys(publicKeyToName).filter((pk) => {
        if (pk === myPublicKey) {
          return !(filenames.includes('me'));
        }
        if (!(pk in contacts)) {
          throw new Error(`Tried to add key that's not in contacts: ${pk}`);
        }
        const sharedKey = sodium.from_base64(contacts[pk]['my-secret']);
        const name = hashfunc(uintConcat(sodium.from_base64(groupSalt), sharedKey));
        return !(filenames.includes(name));
      });
      if (missing.length > 0) {
        throw new Error(`Tried to set nickname of someone not in the group: ${missing.toString()}`);
      }

      // now we can finally set the nicknames
      const groupInfo = await this.getGroupInfo(groupSalt);
      if (groupInfo.members === undefined) {
        groupInfo.members = {};
      }
      Object.assign(groupInfo.members, publicKeyToName);
      const enc = await this.encrypt(groupKey, JSON.stringify(groupInfo));
      await writeFile(node, `/groups/${groupSalt}/info.json.enc`, enc);

      return groupInfo;
    };

    // takes a list of public keys and creates a new group with those people
    //       // does not fill in any optional details, that's left to other functions
    //       //  --> i.e. default group is anonymous, recipients don't know the other recipients
    // actually, I changed my mind about that^ for now
    //  because it's convenient to automatically generate the member list
    // if a given public key is not already in this node's contacts, an error is thrown
    //  --> because this function doesn't know the context for that public key,
    //      and it's important to categorize people (into friends, family, etc) as they come in.
    // returns group name/salt (same thing)
    // groupID is optional. useful if you're trying to semantically link this group to a friend's
    this.createGroup = async (publicKeys, /* optional */ groupID) => {
      await this.sodiumReady();
      await this.ipfsReady();

      const contacts = await this.getContacts();

      const missing = publicKeys.filter(k => !(k in contacts));
      if (missing.length > 0) {
        throw new Error(`Add the following public keys to your contacts first! ${missing}`);
      }

      const salt = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      const groupKey = sodium.crypto_secretbox_keygen();
      const groupdir = `/groups/${sodium.to_base64(salt)}`;

      // create folder for this group
      await node.files.mkdir(groupdir, { parents: true });

      const message = JSON.stringify([sodium.to_base64(groupKey)]);

      const promises = publicKeys.map(async (pk) => {
        const sharedKey = sodium.from_base64(contacts[pk]['my-secret']);
        const name = hashfunc(uintConcat(salt, sharedKey));
        const ciphertext = await this.encrypt(sharedKey, message);
        return writeFile(node, `${groupdir}/${name}`, ciphertext);
      });

      // also add myself to the group
      const sharedKey = await this.getMasterKey();
      const ciphertext = await this.encrypt(sharedKey, message);
      promises.push(writeFile(node, `${groupdir}/me`, ciphertext));

      // generate and add a UUID if an ID wasn't provided
      const groupInfo = {};
      groupInfo.id = groupID || uuidv4();
      const infoEnc = await this.encrypt(groupKey, JSON.stringify(groupInfo));
      promises.push(writeFile(node, `${groupdir}/info.json.enc`, infoEnc));

      await Promise.all(promises);

      // now set all nicknames to "" so everyone knows who's in the group
      const nicknames = {};
      publicKeys.concat([await this.getPublicKey()]).forEach((k) => {
        nicknames[k] = '';
      });
      await this.setNicknames(nicknames, sodium.to_base64(salt));

      return sodium.to_base64(salt);
    };

    this.getGroupList = async () => {
      try {
        return await node.files.ls('/groups')
          .then(flist => flist.map(f => f.name));
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('Got this error in getGroupList but it probably means the folder doesn\'t exist');
          console.log(err);
          return [];
        }
        throw err;
      }
    };

    // returns bio for the given group, or public.json if groupID === 'public'
    this.getBio = async (groupID) => {
      await this.ipfsReady();

      let res;
      try {
        if (groupID === 'public') {
          res = await readFile(node, '/bio/public.json')
            .then(bio => JSON.parse(bio.toString()));
        } else {
          const groupKey = await getGroupKey(groupID).catch(() => {
            // here so we don't mistake an issue with the given groupID
            //  for the file just not existing yet
            throw new Error('[getBio] something is wrong with the groupID');
          });
          const salt = await readFile(node, '/bio/salt');
          const filename = hashfunc(uintConcat(salt, groupKey));
          res = await readFile(node, `/bio/${filename}.json.enc`)
            .then(async bio => JSON.parse(await this.decrypt(groupKey, bio)));
        }
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log("got this error in getBio but we're handling it:");
          console.log(err);
          return {};
        }
        throw err;
      }

      return res;
    };

    // overrides matching fields of bio for the given group, or public.json if groupID === 'public'
    this.setBio = async (groupID, newBio) => {
      await this.sodiumReady();
      await this.ipfsReady();

      const bio = await this.getBio(groupID);
      Object.assign(bio, newBio);

      let salt;
      try {
        salt = await readFile(node, '/bio/salt');
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('got this error in setBio so making new salt');
          console.log(err);
          salt = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
          await writeFile(node, '/bio/salt', salt);
        } else {
          throw err;
        }
      }

      let data = JSON.stringify(bio);
      let filename = 'public.json';
      if (groupID !== 'public') {
        const groupKey = await getGroupKey(groupID);
        data = await this.encrypt(groupKey, data);
        filename = `${hashfunc(uintConcat(salt, groupKey))}.json.enc`;
      }

      return writeFile(node, `/bio/${filename}`, data);
    };

    this.publishProfile = async () => {
      await this.ipfsReady();

      const hash = await this.getMyProfileHash();

      return node.name.publish(`/ipfs/${hash}`, {
        lifetime: '300s', // string - Time duration of the record. Default: 24h
        // ttl:   ,   // string - Time duration this record should be cached
      });
    };

    this.connectToAddr = async (address) => {
      await this.ipfsReady();

      return node.swarm.connect(address);
    };

    this.getIpfsPeers = async () => {
      await this.ipfsReady();

      node.swarm.peers();
    };

    // this function creates the correct folders and sets up all the metadata for a post
    // it DOES NOT write the post data itself (`content.[whatever]`)
    //    because that's going to be different for different posts (regular, react, etc)
    // that part^ must be done OUTSIDE this function
    // this function returns the path to put the post content at
    // this function also does not push the update to IPNS,
    //    that responsibilty lies with the caller as well
    this.setupPostMetadata = async (groupSalt, /* optional  */ parents, tags) => {
      await this.sodiumReady();
      await this.ipfsReady();

      const promisesToWaitFor = [];

      // validate inputs
      // tags should be list of strings
      if (tags !== undefined && tags.some(t => typeof t !== 'string')) {
        throw new Error('tags passed to setupPostMetadata must be strings');
      }
      /* TODO: validate parent paths
          - bare minimum is valid ipfs or ipns path (starting with the '/ip[fn]s/')
          - ideally the path to a post in some profile--
              should be of the form: /ipns/id-of-author/posts/year/month/day/group-secret-salt-hash
      */
      if (parents !== undefined && parents.some(t => typeof t !== 'string')) {
        throw new Error('parents passed to setupPostMetadata must be strings');
      }

      let groupKey;
      try {
        groupKey = await getGroupKey(groupSalt);
      } catch (err) {
        throw new Error(`Got the following error while getting group key for post: ${err}`);
      }

      // TODO: figure out a better way to timestamp. this can be totally off
      /* ideas:
          - ping an external server
          - reconcile with timestamps of recent posts
          - use a network-wide vector clock (not actually crazy maybe?)
      */
      const date = new Date();

      // generate directory if not already there
      const path = `/posts/${date.getUTCFullYear()}/${date.getUTCMonth() + 1}/${date.getUTCDate()}`;
      // month + 1 because it's zero-indexed, but the date is one-indexed
      await node.files.mkdir(path, { parents: true });
      let salt;
      try {
        salt = await readFile(node, `${path}/salt`);
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log("got this error in setupPostMetadata but it probably just means there's no salt yet");
          console.log(err);
          salt = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
          promisesToWaitFor.push(writeFile(node, `${path}/salt`, salt));
        } else {
          throw err;
        }
      }
      // TODO: shorten postdirname. only has to be unique, not secure
      //  so look at what's already there and increment by random value or something
      /* possibly useful but may have to update libsodium:
        console.log(sodium.sodium_bin2base64(271))
      */
      // note: unlike hashfunc, can change this later and it doesn't matter
      const postdirname = sodium.to_base64(sodium.randombytes_buf(9));

      const postdir = `${path}/${hashfunc(uintConcat(salt, groupKey))}/${postdirname}`;
      const mkdirPromise = node.files.mkdir(postdir, { parents: true });

      // write the data
      const meta = {
        // timeStamp
        s: date.getTime(), // milliseconds since Jan 1, 1970
        // TODO: this can be shortened by base64 encoding the int, value unclear
      };
      if (parents) {
        // Parents
        meta.p = parents;
      }
      if (tags) {
        // taGs
        meta.g = tags;
      }
      // ^short names becuase there are going to be a lot of these and every byte counts...

      const metaEnc = await this.encrypt(groupKey, JSON.stringify(meta));
      await mkdirPromise;
      promisesToWaitFor.push(writeFile(node, `${postdir}/meta.json.enc`, metaEnc));

      await Promise.all(promisesToWaitFor);
      return postdir;
    };

    // for posting plaintext
    // returns path to post
    this.postTxt = async (groupSalt, text, /* optional */ parents, tags) => {
      await this.ipfsReady();

      // validate. setupPostMetadata checks the rest
      if (typeof text !== 'string') {
        throw new Error('postTxt requires content to be string');
      }

      const path = this.setupPostMetadata(groupSalt, parents, tags);

      const groupKey = await getGroupKey(groupSalt);
      const contentEnc = await this.encrypt(groupKey, text);
      await writeFile(node, `${await path}/main.txt.enc`, contentEnc);
      return path;
    };

    // for posting reacts
    // decided reacts are best posted by hash since they'll get lots of re-use
    // returns path to post
    this.postReact = async (groupSalt, link, parents) => {
      await this.ipfsReady();

      // validate. TODO: parse link and throw error if it's bad
      if (typeof link !== 'string') {
        throw new Error('postReact requires link to be string');
      }
      if (!parents || parents.some(p => typeof p !== 'string')){
        throw new Error('postReact parents malformed. you must be reacting to something');
      }

      const path = this.setupPostMetadata(groupSalt, parents);

      const groupKey = await getGroupKey(groupSalt);
      const contentEnc = this.encrypt(groupKey, link);
      // note: .lenc is a new file type, for encrypted ipfs links
      //  use sparingly, because it won't be pinned with the profile
      await writeFile(node, `${await path}/main.lenc`, await contentEnc);
      return path;
    };

    // label is how people will refer to it (e.g. :facepalm-7:)
    // image can either be an ipfs link to an existing image or a buffer with the image data itself
    // if image is the image data itself, an extension is required to identify it, e.g. gif, jpg
    // returns ready-to-use ipfs link to that react
    this.createNewReact = async (groupSalt, label_, image, extension_) => {
      await this.ipfsReady();
      await this.sodiumReady();

      // make sure there aren't illegal characters
      const label = label_.replace(/[:\s/]+/g, '');
      if (label !== label_) {
        console.warn('Filtered out illegal label chars in createNewReact');
      }

      const groupKey = getGroupKey(groupSalt);
      // used twice, for different non-cryptographic things so it's ok
      const randomString = sodium.to_base64(sodium.randombytes_buf(10));

      let imagePath;
      if (typeof image === 'string' /* TODO: validate better */) {
        imagePath = image;
      } else {
        // TODO: validate image type. not sure what that's going to be yet. probably buffer

        const extension = extension_.replace(/\.+/g, '');
        const validImageExtensions = ['jpeg', 'jpg', 'png', 'gif'];
        if (!extension) {
          throw new Error('createNewReact with image data needs to know the extension');
        } else if (!(validImageExtensions.includes(extension))) {
          throw new Error('invalid image extension for createNewReact')
        }
        // need to encrypt and write the image
        // TODO: maybe use the streams here? these are not small objects
        imageName = `${sodium.to_base64(sodium.randombytes_buf(10))}.${extension}.enc`;
        const imageEnc = this.encrypt(groupKey, image);
        await writeFile(node, `/groups/${groupSalt}/reacts/${imageName}`, await imageEnc);
        // ^ doesn't return anything. need to look up file for hash
        const hash = await node.files.stat(`/groups/${groupSalt}/reacts/${imageName}`, { hash: true });
        imagePath = `/ipfs/${hash}`
      }

      // now need to write the .react file
      const data = {
        label: label,
        image: imagePath,
      }
      const dataEnc = this.encrypt(groupKey, JSON.stringify(data));
      const path = `/groups/${groupSalt}/reacts/${randomString}.react.enc`;
      await writeFile(node, path, await dataEnc);
      const hash = await node.files.stat(path, { hash: true });
      return `/ipfs/${hash}`;
    }
  }
}


module.exports = GravityProtocol;
