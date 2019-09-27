
const IPFS = require('ipfs');
const { crypto: libp2pcrypto, isIPFS } = require('ipfs');
const ipns = require('ipns');
const multihashing = require('multihashing');
const sodium = require('libsodium-wrappers');
const NodeRSA = require('node-rsa');
const pull = require('pull-stream');
const EventEmitter = require('events');
/* types of events:
 *  new-record: happens when a novel ipns record is ingested
      returns: {
        id: <ipns id that got updated>,
        record: <the record itself>,
        postData: <whatever else came with the 'post' message>,
      }
 */


// logging
const LOG_MESSAGES = true;


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
// TODO: SUPPORT ED25519! the bug was figured out: https://github.com/ipfs/js-ipfs/issues/2261
const encAsymm = async (publicKey, message) => {
  // for now expects publicKey to be a base64-encoded IPFS protobuf-encoded RSA key

  const buf = Buffer.from(publicKey, 'base64');
  // eslint-disable-next-line no-underscore-dangle
  const tempPub = libp2pcrypto.keys.unmarshalPublicKey(buf)._key;

  const key = new NodeRSA();
  key.importKey({
    n: Buffer.from(tempPub.n, 'base64'),
    e: Buffer.from(tempPub.e, 'base64'),
  }, 'components-public');

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

// async filtering, courtesy of https://stackoverflow.com/a/46842181/7343159
async function filter(arr, callback) {
  const fail = Symbol();
  return (await Promise.all(arr.map(async item => ((await callback(item)) ? item : fail)))).filter(i => i !== fail);
}
/* eslint-enable */


//*  the protocol
class GravityProtocol extends EventEmitter {
  constructor(options = {}) {
    super();

    /* options may contain: {
          MIN_IPNS_OUTDATEDNESS,
          deviceKey,
          LIGHT,
    } */

    // when trying to lookup a profile hash, if the current record is within this many millis
    //  of the current time, then the cached version is used instead.
    // useful for heavy-handedly cutting down on rapidly repeated lookups for different purposes
    // setting it to zero should essentially disable it
    const MIN_IPNS_OUTDATEDNESS = options.MIN_IPNS_OUTDATEDNESS || 1000;

    if ('deviceKey' in options) {
      sodium.ready
        .then(() => {
          this.loadDeviceKey(options.deviceKey);
        });
    }

    const node = options.LIGHT ? { ready: true } : new IPFS();

    // make sure to await this before doing anything!
    this.ready = Promise.all([node.ready, sodium.ready]);

    // expose basic utils
    this.to_base64 = sodium.to_base64;
    this.from_base64 = sodium.from_base64;

    // maps ipns IDs ('Qm...') to links and ipns records
    // must be kept in sync with what's stored in the profile
    // duplicated here and there^ for fast lookup (so you don't need to decrypt every time)
    let ipnsMap = {};

    // needed because I override the way ipns resolves
    // takes a /ipns/validID/whatever path and returns /ipfs/validHash/whatever
    const resolveIpnsLink = async (path, cacheOnly = true) => {
      const split = path.slice(6).split('/');
      const id = split[0];
      let base;
      if (!cacheOnly || !(id in ipnsMap) || id === (await this.getIpnsId())) {
        base = await this.lookupProfileHash({ ipnsId: id });
      } else {
        base = ipnsMap[id].value;
      }
      // TODO: make recursive if the result is another ipns link? maybe
      return `${base}/${split.slice(1).join('/')}`;
    };

    // *** utils to handle basic ip[fn]s functions for any path ***
    const readGenerator = (func, mfsFunc, name = 'readGenerator') => async function inner(path) {
      try {
        if (isIPFS.ipfsPath(path) || isIPFS.cid(path)) {
          return await func(path).then(async (res) => {console.log(res); console.log(Buffer.from(await (await fetch('https://ipfs.io'.concat(path))).arrayBuffer())); return res});
        }
        if (/^\/ipns\//.test(path)) {
          // it's an ipns link, need to resolve the ID
          return await inner(await resolveIpnsLink(path));
        }
        if (/^\//.test(path)) {
          // last resort... maybe MFS path?
          return await mfsFunc(path);
        }
        throw new Error(`invalid path in ${name}: ${path}`);
      } catch (err) {
        console.log(`got this error in ${name} for path ${path}`);
        throw err;
      }
    };
    const cat = readGenerator(node.cat, node.files.read, 'cat');
    // const cat = readGenerator((path) => fetch('https://ipfs.io'.concat(path)), node.files.read, 'cat');
    const ls = readGenerator(node.ls, node.files.ls, 'ls');
    this.ls = ls;
    this.cat = cat;

    // for debugging
    this.getIpnsInfo = () => {
      console.log(ipnsMap);

      const readable = {};
      Object.keys(ipnsMap).forEach((k) => {
        readable[k] = Object.assign({}, ipnsMap[k]);
        readable[k].signature = sodium.to_base64(readable[k].signature);
        readable[k].pubKey = sodium.to_base64(readable[k].pubKey);
        readable[k].validity = sodium.to_base64(readable[k].validity);
      });
      return readable;
    };

    this.getNodeInfo = async () => node.id();

    // returns this instance's public key
    this.getPublicKey = async () => (await this.getNodeInfo()).publicKey;

    this.getIpnsId = async () => (await this.getNodeInfo()).id;

    // converts public keys (string or buffer) into the IPNS formatted short IDs
    this.pubkeyToIpnsId = (pk) => {
      if (typeof pk === 'string' || pk instanceof String) {
        return multihashing.multihash.toB58String(multihashing(Buffer.from(pk, 'base64'), 'sha2-256'));
      }
      return multihashing.multihash.toB58String(multihashing(pk, 'sha2-256'));
    };

    const ipnsIdToPubkeyCache = {};
    // only works if the person in question is in your contacts
    // TODO: improve this, there's definitely an IPFS way
    this.ipnsIdToPubkey = async (id) => {
      if (id in ipnsIdToPubkeyCache) {
        return ipnsIdToPubkeyCache[id];
      }
      if (id === await this.getIpnsId()) {
        ipnsIdToPubkeyCache[id] = await this.getPublicKey();
        return ipnsIdToPubkeyCache[id];
      }
      // generate the chache for all contacts
      await Promise.all(Object.keys(await this.getContacts()).map(async (pk) => {
        ipnsIdToPubkeyCache[await this.pubkeyToIpnsId(pk)] = pk;
      }));

      if (id in ipnsIdToPubkeyCache) {
        return ipnsIdToPubkeyCache[id];
      }
      throw new Error(`couldn't find public key for id: ${id}`);
    };

    this.loadDirs = async path => loadDirs(node, path);

    // this is the key stored locally on the current device
    // used to get the master key to do everything else
    let deviceKey;

    // for external use. you need to have a device key to unlock the master key used for everything
    this.loadDeviceKey = (key) => {
      if (typeof key === 'string') {
        deviceKey = sodium.from_base64(key);
      } else {
        deviceKey = key;
      }
    };

    this.getDeviceKeyInfo = async () => {
      const mk = this.getMasterKey();
      let enc;
      try {
        enc = await cat('/device-keys/info.json.enc');
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log("got this error in getDeviceKeyInfo but we're handling it:", err.message);
          return {};
        }
        console.warn('unexpected error in getDeviceKeyInfo');
        throw err;
      }
      return JSON.parse(await this.decrypt(await mk, enc));
    };

    const writeDeviceKeyInfo = async (info, masterKey = undefined) => {
      let mk = masterKey;
      if (!mk) mk = await this.getMasterKey();
      const enc = this.encrypt(mk, JSON.stringify(info));
      return writeFile(node, '/device-keys/info.json.enc', await enc);
    };

    this.setDeviceKeyDescription = async (key, desc) => {
      const name = hashfunc(key);
      const info = await this.getDeviceKeyInfo();
      info[name] = desc;
      return writeDeviceKeyInfo(info);
    };

    // `name` is the hash of the key to remove (likely learned from getDeviceKeyInfo)
    this.removeDeviceKey = async (name) => {
      const prom = node.files.rm(`/device-keys/${name}`, { recursive: true }).catch(() => {});
      const info = await this.getDeviceKeyInfo();
      delete info[name];
      return Promise.all([prom, writeDeviceKeyInfo(info)]);
    };

    // if no master key given, uses existing device key to create another key
    // loads the new key for future use, and returns a copy of it
    this.createNewDeviceKey = async (description, masterKey = undefined) => {
      const dk = sodium.crypto_secretbox_keygen();
      const name = hashfunc(dk);
      let mk = masterKey;
      if (!mk) mk = await this.getMasterKey();

      const enc = await this.encrypt(dk, sodium.to_base64(mk));
      await writeFile(node, `/device-keys/${name}`, enc);
      // now ready to use
      this.loadDeviceKey(dk);

      await this.setDeviceKeyDescription(dk, description);
      return dk;
    };

    // since this gets used a ton, might as well cache
    let masterKeyCache;

    // ! use with extreme caution !
    // clears device keys, makes a new master key, and returns a new device key with access to it
    this.resetMasterKey = async () => {
      // the line of no return:
      await node.files.rm('/device-keys', { recursive: true }).catch(() => {});

      // make the new keys
      const mk = sodium.crypto_secretbox_keygen();
      const dk = await this.createNewDeviceKey('first key', mk);

      masterKeyCache = mk;
      return dk;
    };

    this.getMasterKey = async () => {
      if (masterKeyCache) return masterKeyCache;
      if (deviceKey === undefined) {
        throw new Error('Can\'t get master key, no device key loaded');
      }
      const name = hashfunc(deviceKey);
      const enc = await cat(`/device-keys/${name}`);
      masterKeyCache = sodium.from_base64(await this.decrypt(deviceKey, enc));
      return masterKeyCache;
    };

    this.encrypt = async (key, message) => {
      // also prepends nonce

      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      return uintConcat(nonce, sodium.crypto_secretbox_easy(message, nonce, key));
    };

    this.decrypt = async (key, nonceAndCiphertext) => {
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
    this.getMyProfileHash = async () => (await node.files.stat('/')).hash;

    this.getContacts = async () => {
      const mkey = await this.getMasterKey();
      return cat('/private/contacts.json.enc')
        .then(async contacts => JSON.parse(await this.decrypt(mkey, contacts)))
        .catch((err) => {
          if (err.message.includes('exist')) {
            console.log("got this error in getContacts but we're handling it:", err.message);
            return {};
          }
          console.warn('unexpected error in getContacts');
          throw err;
        });
    };

    this.setAddrs = async (publicKey, newAddrs) => {
      const contacts = await this.getContacts();
      if (Object.prototype.toString.call(newAddrs) !== '[object Array]') {
        throw new Error(`setAddrs expects newAddrs to be array. got: ${newAddrs}`);
      }
      if (!(publicKey in contacts)) {
        throw new Error(`tried to set addr of key not in contacts: ${publicKey}`);
      }
      contacts[publicKey].addresses = newAddrs;
      const encContacts = await this.encrypt(await this.getMasterKey(), JSON.stringify(contacts));
      return writeFile(node, '/private/contacts.json.enc', encContacts);
    };

    // checks if already in contacts
    // adds a file in the subscribers folder for this friend so they can find the shared secret
    // adds them as contact (record shared secret, etc)
    this.addSubscriber = async (publicKey) => {
      // note: choosing to do everything with their public key
      //  because it's easier to go from public key to IPNS id (Qm...8g) than vice versa

      if (publicKey === await this.getPublicKey()) {
        throw new Error('Tried to add self as subscriber');
      }

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
    };

    // given the path to the top level folder of someone else's profile,
    // try to decrypt each blob in order to find the one intended for you
    // returns the shared secret as buffer/Uint8Array
    this.testDecryptAllSubscribers = async (path) => {
      // TODO: check if the one you remember (from contacts) is still there first,
      //    in a function that would otherwise call this

      // eslint-disable-next-line no-underscore-dangle
      const privateKey = node._peerInfo.id._privKey._key;

      const lst = await ls(`${path}/subscribers`);

      const promises = lst.map(async (obj) => {
        const ciphertext = await cat(obj.hash);

        // RSA lib will err if key is wrong. this is good. it gets trapped in the promise correctly
        const res = (await decAsymm(privateKey, ciphertext)).toString();

        if (res.slice(0, 5) !== 'Hello') {
          throw new Error('Decrypted message not in the correct format');
        }

        return res.split(': ').pop();
      });

      return sodium.from_base64(await returnSuccessful(promises));
    };

    // returns the group key for the given group
    // TODO: no 'this' to make it harder to accidentally mishandle keys
    //    nontrivial because you need it for client-side lazy loading of post data
    //    one idea: expose an encrypted copy of the key that I can just dec and use here?
    this.getGroupKey = async (publicKey, groupSalt_) => {
      let groupSalt = groupSalt_;
      if (typeof groupSalt_ !== 'string') {
        groupSalt = sodium.to_base64(groupSalt_);
      }

      let groupKeyBuf;
      if (publicKey === await this.getPublicKey()) {
        const masterKey = await this.getMasterKey();
        groupKeyBuf = this.decrypt(masterKey, await cat(`/groups/${groupSalt}/me`));
      } else {
        const key = await this.getFriendKey(publicKey);

        const friendPath = this.lookupProfileHash({ publicKey });
        const salt = sodium.from_base64(groupSalt);
        const hash = hashfunc(uintConcat(salt, key));
        groupKeyBuf = this.decrypt(key, await cat(`${await friendPath}/groups/${groupSalt}/${hash}`));
      }
      return sodium.from_base64(JSON.parse((await groupKeyBuf).toString())[0]);
    };

    // returns the info JSON for the given group
    this.getGroupInfo = async (groupSalt, publicKey) => {
      const groupKey = this.getGroupKey(publicKey, groupSalt);
      let enc;
      try {
        const path = await this.lookupProfileHash({ publicKey });
        enc = await cat(`${path}/groups/${groupSalt}/info.json.enc`);
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('Got this error in getGroupInfo but it probably just means there was no group info:', err.message);
          return {};
        }
        console.warn('unexpected error in getGroupInfo');
        throw err;
      }
      return JSON.parse(await this.decrypt(await groupKey, enc));
    };

    /*  .cmd type posts are for updating group state.
     *  Since everyone maintains their own version of the group state,
     *    you have to tell everyone when you change something so they can update their copy.
     *  Command is the function used to update the state: addToGroup, setNickname, etc.
     *  Args are the args to pass to that function, as a list (later to be used like cmd(...args); )
     *
     *  This function isn't exposed because you should never use it directly,
     *    it should only happen as a byproduct of doing the state changes you're reporting.
     *
     *  Also, don't forget to check for these in your app and do something about them! (i.e. doCmd)
     */
    const postCmd = async (groupSalt, command, args) => {
      if (typeof command !== 'string') {
        throw new Error('postCmd command should be a string');
      }
      if (Object.prototype.toString.call(args) !== '[object Array]') {
        throw new Error('postCmd args should be a list');
      }

      const path = this.setupPostMetadata(groupSalt);

      const groupKey = this.getGroupKey(await this.getPublicKey(), groupSalt);

      const cmdObj = {
        cmd: command,
        args,
      };
      const contentEnc = await this.encrypt(await groupKey, JSON.stringify(cmdObj));
      await writeFile(node, `${await path}/main.cmd`, contentEnc);
      return `/ipns/${await this.getIpnsId()}/${await path}`;
    };

    // takes a cmd object (the JSON in main.cmd) and does the appropriate update
    this.doCmd = async (groupSalt, cmdObj) => {
      const names = ['addToGroup', 'setGroupName', 'setNicknames'];
      const funcs = [this.addToGroup, this.setGroupName, this.setNicknames];
      const ind = names.indexOf(cmdObj.cmd);
      if (ind === -1) throw new Error(`unsupported command: ${cmdObj.cmd}`);

      return funcs[ind](groupSalt, ...cmdObj.args);
    };

    // takes an object mapping public keys to nicknames (so you can do many at once)
    // sets the nicknames for those people in the group corresponding to groupSalt
    this.setNicknames = async (groupSalt, publicKeyToName) => {
      // first make sure everyone is in the group
      const contacts = await this.getContacts();
      const filenames = await ls(`/groups/${groupSalt}`)
        .then(flist => flist.map(f => f.name));
      const myPublicKey = await this.getPublicKey();
      const groupKey = await this.getGroupKey(myPublicKey, groupSalt);

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
      const groupInfo = await this.getGroupInfo(groupSalt, myPublicKey);
      if (groupInfo.members === undefined) {
        groupInfo.members = {};
      }

      const namesChanged = Object.keys(publicKeyToName).filter(pk =>
        // eslint-disable-next-line implicit-arrow-linebreak
        publicKeyToName[pk] !== groupInfo.members[pk]);
      if (namesChanged.length === 0) {
        return groupInfo;
      }

      Object.assign(groupInfo.members, publicKeyToName);
      const enc = await this.encrypt(groupKey, JSON.stringify(groupInfo));
      await writeFile(node, `/groups/${groupSalt}/info.json.enc`, enc);

      // send a .cmd to the group alerting others to the change
      await postCmd(groupSalt, 'setNicknames', [publicKeyToName]);

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
    this.createGroup = async (publicKeys_, /* optional */ groupID) => {
      const mypk = await this.getPublicKey();
      const publicKeys = publicKeys_.filter(k => k !== mypk);

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

      const promises = [];

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

      await this.addToGroup(sodium.to_base64(salt), publicKeys);

      // now set all nicknames to "" so everyone knows who's in the group
      const nicknames = {};
      nicknames[mypk] = '';
      await this.setNicknames(sodium.to_base64(salt), nicknames);

      return sodium.to_base64(salt);
    };

    // salt should be a string
    this.addToGroup = async (salt, publicKeys_) => {
      const mypk = await this.getPublicKey();
      let publicKeys = publicKeys_.filter(k => k !== mypk);

      if (publicKeys.length === 0) {
        console.warn('addToGroup called with empty list (or your own pubkey)');
        return;
      }

      const contacts = await this.getContacts();
      const missing = publicKeys.filter(k => !(k in contacts));
      if (missing.length > 0) {
        throw new Error(`Add the following public keys to your contacts first! ${missing}`);
      }

      const groupKey = await this.getGroupKey(mypk, salt);
      const groupdir = `/groups/${salt}`;

      const message = JSON.stringify([sodium.to_base64(groupKey)]);

      const files = (await ls(groupdir)).map(f => f.name);

      const promises = publicKeys.map(async (pk) => {
        const sharedKey = sodium.from_base64(contacts[pk]['my-secret']);
        const name = hashfunc(uintConcat(sodium.from_base64(salt), sharedKey));
        // check if they're already in the group
        if (files.includes(name)) return undefined;
        // need to record the ones who weren't by returning pk
        const ciphertext = await this.encrypt(sharedKey, message);
        await writeFile(node, `${groupdir}/${name}`, ciphertext);
        return pk;
      });

      // filter out all the ones that were already there
      publicKeys = (await Promise.all(promises)).filter(pk => pk !== undefined);
      if (publicKeys.length === 0) {
        console.warn('all public keys being added were already in the group');
        return;
      }

      // send a .cmd to the group alerting others to the change
      await postCmd(salt, 'addToGroup', [publicKeys]);

      // now set all nicknames to "" so everyone knows who's in the group
      const nicknames = {};
      publicKeys.forEach((k) => {
        nicknames[k] = '';
      });
      await this.setNicknames(salt, nicknames);
    };

    // sets the 'name' field in the group info
    this.setGroupName = async (groupSalt, newName) => {
      if (typeof newName !== 'string') throw new Error('group name should be string');

      const groupInfo = await this.getGroupInfo(groupSalt, await this.getPublicKey());

      // check if it's actually changing
      if (groupInfo.name === newName) return groupInfo;

      groupInfo.name = newName;
      const groupKey = await this.getGroupKey(await this.getPublicKey(), groupSalt);
      const enc = await this.encrypt(groupKey, JSON.stringify(groupInfo));
      await writeFile(node, `/groups/${groupSalt}/info.json.enc`, enc);

      // send a .cmd to the group alerting others to the change
      await postCmd(groupSalt, 'setGroupName', [newName]);

      return groupInfo;
    };

    // gets the list of groups you're in
    this.getGroupList = async (publicKey) => {
      try {
        if (publicKey === await this.getPublicKey()) {
          return await ls('/groups')
            .then(flist => flist.map(f => f.name));
        }

        const key = this.getFriendKey(publicKey);

        const friendPath = await this.lookupProfileHash({ publicKey });
        const groups = await ls(`${friendPath}/groups`)
          .then(flist => flist.map(f => f.name));

        return filter(groups, async (g) => {
          // check if there's a folder corresponding to your shared key
          const files = ls(`${friendPath}/groups/${g}`)
            .then(flist => flist.map(f => f.name));
          const salt = sodium.from_base64(g);
          return (await files).includes(hashfunc(uintConcat(salt, await key)));
        });
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('Got this error in getGroupList but it probably means the folder doesn\'t exist:', err.message);
          return [];
        }
        throw err;
      }
    };

    // returns bio for the given group, or public.json if groupSalt === 'public'
    this.getBio = async (publicKey, groupSalt) => {
      const path = await this.lookupProfileHash({ publicKey });
      try {
        if (groupSalt === 'public') {
          return await cat(`${path}/bio/public.json`)
            .then(bio => JSON.parse(bio.toString()));
        }
        const groupKey = await this.getGroupKey(publicKey, groupSalt).catch(() => {
          // here so we don't mistake an issue with the given groupSalt
          //  for the file just not existing yet
          throw new Error('[getBio] something is wrong with the groupSalt');
        });
        const salt = await cat(`${path}/bio/salt`);
        const filename = hashfunc(uintConcat(salt, groupKey));
        return await cat(`${path}/bio/${filename}.json.enc`)
          .then(async bio => JSON.parse(await this.decrypt(groupKey, bio)));
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log("got this error in getBio but we're handling it:", err.message);
          return {};
        }
        console.warn('unexpected error in getBio');
        throw err;
      }
    };

    // overrides matching fields of bio for the given group or public.json if groupSalt === 'public'
    this.setBio = async (groupSalt, newBio) => {
      const bio = await this.getBio(await this.getPublicKey(), groupSalt);
      Object.assign(bio, newBio);

      let salt;
      try {
        salt = await cat('/bio/salt');
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log('got this error in setBio so making new salt:', err.message);
          salt = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
          await writeFile(node, '/bio/salt', salt);
        } else {
          throw err;
        }
      }

      let data = JSON.stringify(bio);
      let filename = 'public.json';
      if (groupSalt !== 'public') {
        const groupKey = await this.getGroupKey(await this.getPublicKey(), groupSalt);
        data = await this.encrypt(groupKey, data);
        filename = `${hashfunc(uintConcat(salt, groupKey))}.json.enc`;
      }

      return writeFile(node, `/bio/${filename}`, data);
    };

    // publishes profile and alerts everyone in the list of addrs
    //  useful if you update your profile with a DM for one person; no need to alert everyone else
    // appends `additionalData` to the post, for if you want to send extra stuff (like what changed)
    this.publishProfile = async (/* optional */ addrs, additionalData) => {
      const info = await this.getNodeInfo();
      const myIpnsId = info.id;
      const privateKey = node._peerInfo.id._privKey; // eslint-disable-line no-underscore-dangle
      const publicKey = node._peerInfo.id._pubKey; // eslint-disable-line no-underscore-dangle

      const value = `/ipfs/${await this.getMyProfileHash()}`;
      const sequenceNumber = Date.now();
      const lifetime = 365 * 24 * 60 * 60 * 1000; // ms
      const record = await new Promise((resolve, reject) => {
        ipns.create(privateKey, value, sequenceNumber, lifetime, (err, rec) => {
          if (err) { reject(err); }
          ipns.embedPublicKey(publicKey, rec, (err2, rec2) => {
            if (err2) { reject(err2); } else { resolve(rec2); }
          });
        });
      });

      ipnsMap[myIpnsId] = record;
      const message = `p ${sodium.to_base64(ipns.marshal(record))} ${additionalData}`;

      // if addresses not provided, send to all contacts
      let addrsToTry = addrs;
      if (addrsToTry === undefined) {
        const contacts = await this.getContacts();

        addrsToTry = Object.keys(contacts).map(k =>
        // eslint-disable-next-line implicit-arrow-linebreak
          (contacts[k].addresses ? contacts[k].addresses : [])).flat();
      }

      addrsToTry.forEach((addr) => {
        this.sendToPeer(addr, message)
          .catch((err) => {
            console.log(`failed to publish to peer: ${addr}`);
            console.log(err);
          });
      });
    };

    this.connectToAddr = async address => node.swarm.connect(address);

    this.getIpfsPeers = async () => node.swarm.peers();

    // this function creates the correct folders and sets up all the metadata for a post
    // it DOES NOT write the post data itself (`content.[whatever]`)
    //    because that's going to be different for different posts (regular, react, etc)
    // that part^ must be done OUTSIDE this function
    // this function returns the path to put the post content at
    // this function also does not push the update to IPNS,
    //    that responsibilty lies with the caller as well
    // CAUTION: returned path is MFS (/posts/...), not a true path (/ipns/myId/posts/...)
    //    DO NOT USE THIS PATH except to write stuff into the folder
    this.setupPostMetadata = async (groupSalt, /* optional  */ parents, tags) => {
      const promisesToWaitFor = [];

      // validate inputs
      // tags should be list of strings
      if (tags !== undefined && tags.some(t => typeof t !== 'string')) {
        throw new Error('tags passed to setupPostMetadata must be strings');
      }
      /* validate parent paths
          bare minimum is valid ipfs or ipns path (starting with '/ip[fn]s/')
          ideally the path to a post in some profile--
              should be of the form: /ipns/id-of-author/posts/year/month/day/group-secret-salt-hash
            but it could be useful to reply to arbitrary ipfs content so that's not enforced
      */
      if (parents !== undefined && parents.some(p => !isIPFS.path(p))) {
        throw new Error('invalid parents passed to setupPostMetadata');
      }

      let groupKey;
      try {
        groupKey = await this.getGroupKey(await this.getPublicKey(), groupSalt);
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
        salt = await cat(`${path}/salt`);
      } catch (err) {
        if (err.message.includes('exist')) {
          console.log("got this error in setupPostMetadata but it probably just means there's no salt yet:", err.message);
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
      // note: unlike hashfunc, can change this naming system later and it doesn't matter
      const postdirname = sodium.to_base64(sodium.randombytes_buf(9));

      const postdir = `${path}/${hashfunc(uintConcat(salt, groupKey))}/${postdirname}`;
      const mkdirPromise = node.files.mkdir(postdir, { parents: true });

      // write the data
      const meta = {
        // timeStamp
        s: date.getTime(), // milliseconds since Jan 1, 1970
        // TODO: this can be shortened by base64 encoding the int, value unclear
      };
      if (parents && parents.length > 0) {
        // Parents
        meta.p = parents;
      }
      if (tags && tags.length > 0) {
        // taGs
        meta.g = tags;
      }
      // ^short names becuase there are going to be a lot of these and every byte counts...

      const metaEnc = await this.encrypt(groupKey, JSON.stringify(meta));
      await mkdirPromise;
      promisesToWaitFor.push(writeFile(node, `${postdir}/meta.json`, metaEnc));
      // NOTE: meta.json is encrypted but doesn't have .enc
      //  because there are going to be a ton of these so it saves a lot of space.
      // There's no ambiguity because everything in a post is always encrypted.

      await Promise.all(promisesToWaitFor);
      return postdir;
    };

    // for posting plaintext
    // returns path to post
    this.postTxt = async (groupSalt, text, /* optional */ parents, tags) => {
      // validate. setupPostMetadata checks the rest
      if (typeof text !== 'string') {
        throw new Error('postTxt requires content to be string');
      }

      const path = this.setupPostMetadata(groupSalt, parents, tags);

      const groupKey = await this.getGroupKey(await this.getPublicKey(), groupSalt);
      const contentEnc = await this.encrypt(groupKey, text);
      await writeFile(node, `${await path}/main.txt`, contentEnc);
      return `/ipns/${await this.getIpnsId()}/${await path}`;
    };

    // for posting reacts
    // decided reacts are best posted by hash since they'll get lots of re-use
    // returns path to post
    this.postReact = async (groupSalt, link, parents) => {
      if (true) { throw new Error('not in MVP'); } // AKA untested and unused

      // validate
      if (!isIPFS.ipfsPath(link)) {
        throw new Error('postReact link must be valid IPFS path');
      }
      if (!parents) { // rest is checked in setupPostMetadata
        throw new Error('no postReact parents; you must be reacting to something');
      }

      const path = this.setupPostMetadata(groupSalt, parents);

      const groupKey = await this.getGroupKey(await this.getPublicKey(), groupSalt);
      const contentEnc = this.encrypt(groupKey, link);
      // note: .lenc is a new file type, for encrypted ipfs links
      //  use sparingly, because it won't be pinned with the profile
      await writeFile(node, `${await path}/main.lenc`, await contentEnc);
      return `/ipns/${await this.getIpnsId()}/${await path}`;
    };

    // label is how people will refer to it (e.g. :facepalm-7:)
    // image can either be an ipfs link to an existing image or a buffer with the image data itself
    // if image is the image data itself, an extension is required to identify it, e.g. gif, jpg
    // returns ready-to-use ipfs link to that react
    this.createNewReact = async (groupSalt, label_, image, extension_) => {
      if (true) { throw new Error('not in MVP'); } // AKA untested and unused

      // make sure there aren't illegal characters
      const label = label_.replace(/[:\s/]+/g, '');
      if (label !== label_) {
        console.warn('Filtered out illegal label chars in createNewReact');
      }

      const groupKey = this.getGroupKey(await this.getPublicKey(), groupSalt);
      // used twice, for different non-cryptographic things so it's ok
      const randomString = sodium.to_base64(sodium.randombytes_buf(10));

      let imagePath;
      if (isIPFS.ipfsPath(image)) {
        imagePath = image;
      } else {
        // TODO: validate image type. not sure what that's going to be yet. probably buffer

        const extension = extension_.replace(/\.+/g, '');
        const validImageExtensions = ['jpeg', 'jpg', 'png', 'gif'];
        if (!extension) {
          throw new Error('createNewReact with image data needs to know the extension');
        } else if (!(validImageExtensions.includes(extension))) {
          throw new Error('invalid image extension for createNewReact');
        }
        // need to encrypt and write the image
        // TODO: maybe use the streams here? these are not small objects
        const imageName = `${sodium.to_base64(sodium.randombytes_buf(10))}.${extension}.enc`;
        const imageEnc = this.encrypt(groupKey, image);
        await writeFile(node, `/groups/${groupSalt}/reacts/${imageName}`, await imageEnc);
        // ^ doesn't return anything. need to look up file for hash
        const hash = await node.files.stat(`/groups/${groupSalt}/reacts/${imageName}`, { hash: true });
        imagePath = `/ipfs/${hash}`;
      }

      // now need to write the .react file
      const data = {
        label,
        image: imagePath,
      };
      const dataEnc = this.encrypt(groupKey, JSON.stringify(data));
      const path = `/groups/${groupSalt}/reacts/${randomString}.react.enc`;
      await writeFile(node, path, await dataEnc);
      const hash = await node.files.stat(path, { hash: true });
      return `/ipfs/${hash}`;
    };

    // this is what you share to get people to add you
    // TODO: make it an actual URL-safe link
    this.getMagicLink = async () => {
      const info = await this.getNodeInfo();
      return JSON.stringify({
        publicKey: info.publicKey,
        addresses: info.addresses,
      });
    };

    this.addViaMagicLink = async (magicLink) => {
      const magic = JSON.parse(magicLink);

      if (!('publicKey' in magic)) {
        throw new Error('magic link missing some info');
      }
      const pubkey = magic.publicKey;
      await this.addSubscriber(pubkey);

      const contacts = await this.getContacts();

      if (contacts[pubkey].addresses) {
        // remove duplicates
        // eslint-disable-next-line max-len
        contacts[pubkey].addresses = [...new Set(magic.addresses.concat(contacts[pubkey].addresses))];
      } else {
        contacts[pubkey].addresses = magic.addresses;
      }

      const encContacts = this.encrypt(await this.getMasterKey(), JSON.stringify(contacts));
      await writeFile(node, '/private/contacts.json.enc', await encContacts);
    };

    // try connecting to all your friends
    this.autoconnectPeers = async () => {
      // wait until you have a few ipfs peers to bootstrap of off
      // TODO: you could actually check this, but it's not ideal to rely on them anyways
      // TODO: first explore how feasible it is to do this without the middleman
      await sleep(2000);

      const contacts = await this.getContacts();
      console.log('Attempting to connect to many old addresses...');
      Object.keys(contacts).forEach((key) => {
        if (contacts[key].addresses) {
          contacts[key].addresses.forEach((addr) => {
            this.connectToAddr(addr)
              .catch(err => console.log(err.message));
          });
        }
      });

      // TODO: find a better way of indicating success or failure
      await sleep(2000);
    };

    // sends message to the specified peer address
    this.sendToPeer = async (addr, message) => { // eslint-disable-line arrow-body-style
      /* TODO: keep one connection open and reuse it like so:
          https://github.com/libp2p/js-libp2p/blob/master/examples/chat/src/dialer.js
          - don't forget to handle connections opening/closing randomly even if peers still online
            (https://github.com/ipfs/js-ipfs/issues/2288)
      */
      return new Promise((resolve, reject) => {
        node.libp2p.dialProtocol(addr, '/gravity/0.0.1', (err, conn) => {
          if (err) {
            reject(err);
          }
          pull(pull.values([message]), conn, pull.collect((err2, data) => {
            if (err2) {
              reject(err2);
            }
            if (LOG_MESSAGES) { console.log(`got response: ${data.toString().slice(0, 12)}...`); }

            const split = data.toString().split(/\s+/);

            if (split[0] === 'p') { // post
              resolve(this.handlePost(split));
            }

            resolve();
          }));
        });
      });
    };

    const getIpnsRecordStore = async () => {
      const mk = await this.getMasterKey();
      try {
        const files = (await ls('/private/records')).map(f => f.name);
        const savedMap = {};

        await Promise.all(files.map(async (f) => {
          const data = await cat(`/private/records/${f}`);
          const item = JSON.parse(await this.decrypt(mk, data));
          const id = Object.keys(item)[0];
          savedMap[id] = item[id];
        }));

        Object.keys(savedMap).forEach((pk) => {
          savedMap[pk].pubKey = Buffer.from(savedMap[pk].pubKey);
          savedMap[pk].signature = Buffer.from(savedMap[pk].signature);
          savedMap[pk].validity = Buffer.from(savedMap[pk].validity);
        });

        return savedMap;
      } catch (err) {
        if (err.message.includes('exist')) {
          // I think this should only happen if the profile in question has no /posts dir
          console.log("got this error in getIpnsRecordStore but we're handling it:", err.message);
          return {};
        }
        console.warn('unexpected error in getIpnsRecordStore');
        throw err;
      }
    };

    // long-term storage, as opposed to ipnsMap
    // for when you reload later and no one else is online
    const storeIpnsRecord = async (id, record) => {
      const mk = await this.getMasterKey();
      // the '0' is in case I feel like changing this convention
      //  -- I can just increment it and easily tell them apart
      // also, space isn't really a constraint here so making the name longer is fine
      const name = '0'.concat(hashfunc(uintConcat(mk, multihashing.multihash.fromB58String(id))));
      // the point here is just to have a deterministic name for this file
      //  that also doesn't reveal whose records they are (hence mixing in the master key)
      const recordObj = {};
      recordObj[id] = record;
      const enc = await this.encrypt(mk, JSON.stringify(recordObj));
      return writeFile(node, `/private/records/${name}.json.enc`, enc);
    };

    // simple function, just takes a post request and sends it to the next thing
    // exists because it happens in two places, and DRY
    this.handlePost = async split => this.ingestIpnsRecord(split[1], { postData: split.splice(2).join(' ') });

    // checks if the new record is valid and more recent. if so, updates our list
    this.ingestIpnsRecord = async (newRecordProto64, /* optional */ additionalEventData = {}) => {
      // convenient to save the record as an object
      const newRecord = ipns.unmarshal(sodium.from_base64(newRecordProto64));
      newRecord.value = Buffer.from(newRecord.value).toString();
      // these all need to be buffers
      // TODO: submit github issue to js-ipns if it's still like this in the new version
      newRecord.pubKey = Buffer.from(newRecord.pubKey);
      newRecord.signature = Buffer.from(newRecord.signature);
      newRecord.validity = Buffer.from(newRecord.validity);

      const ipnsId = this.pubkeyToIpnsId(newRecord.pubKey);

      if (!ipnsMap[ipnsId] || newRecord.sequence > ipnsMap[ipnsId].sequence) {
        // the new record is more recent

        const pubKey = await new Promise((resolve, reject) => {
          ipns.extractPublicKey({ pubKey: 'dummy' }, newRecord, (err, pk) => {
            if (err) { reject(err); } else { resolve(pk); }
          });
        });
        if (pubKey === 'dummy') {
          console.warn("public key wasn't attached to record");
          return;
        }

        try {
          await new Promise((resolve, reject) => {
            ipns.validate(pubKey, newRecord, (err) => {
              // if no error, the record is valid
              if (err) { reject(err); }
              resolve();
            });
          });
        } catch (err) {
          console.warn(err);
          return;
        }

        // emit an event if this is really new content
        if (ipnsMap[ipnsId] === undefined || ipnsMap[ipnsId].value !== newRecord.value) {
          this.emit('new-record', Object.assign(additionalEventData, { id: ipnsId, record: newRecord }));
        }

        // note the last time this entry was checked
        newRecord.lastCheck = Date.now();

        ipnsMap[ipnsId] = newRecord;
        // this is async but it doesn't matter really when it finishes, just a background task
        storeIpnsRecord(ipnsId, newRecord);
      }
    };

    // returns the most recent top level hash of the profile associated with the given public key
    // will query peers for most up to date value if timeout is nonzero, otherwise pulls from cache
    // needs either an IPNS ID or a public key. will prefer IPNS ID if both are given
    this.lookupProfileHash = async ({
      publicKey,
      ipnsId: ipnsId_,
      timeout = 1000,
    } = {}) => {
      let ipnsId;
      if (ipnsId_ !== undefined && isIPFS.cid(ipnsId_)) {
        ipnsId = ipnsId_;
      } else {
        ipnsId = this.pubkeyToIpnsId(publicKey);
      }

      if (ipnsId === (await this.getIpnsId())) {
        return `/ipfs/${await this.getMyProfileHash()}`;
      }

      // check if the most recent record was refreshed recently enough,
      //  as determined by MIN_IPNS_OUTDATEDNESS
      if (ipnsId in ipnsMap
          && Math.abs(Date.now() - ipnsMap[ipnsId].lastCheck) < MIN_IPNS_OUTDATEDNESS) {
        return ipnsMap[ipnsId].value;
      }

      if (timeout) {
        const contacts = await this.getContacts();
        // TODO: this can be an interesting and complicated strategy
        //  for example, you could only ask people in a certain more trusted group
        //  or you could try a few people first, and then more if that fails
        // for now, ask everyone at once
        const addrsToTry = Object.keys(contacts).map(k =>
        // eslint-disable-next-line implicit-arrow-linebreak
          (contacts[k].addresses ? contacts[k].addresses : [])).flat();

        addrsToTry.forEach((addr) => {
          this.sendToPeer(addr, `g ${ipnsId}`)
            .catch((err) => {
              console.log(`failed asking peer for help: ${addr}`, '\nerror msg:', err.message);
            });
        });

        // TODO: there's a way better way to do this with promises.
        //  have sendPeer resolve on a response and wait for any response (or settimeout to resolve)
        await sleep(timeout);
      }

      if (ipnsMap[ipnsId] === undefined) {
        throw new Error('could not find IPNS record before timeout :(');
      }

      // note the last time this entry was checked
      ipnsMap[ipnsId].lastCheck = Date.now();

      return ipnsMap[ipnsId].value;
    };

    this.getFriendKey = async (publicKey) => {
      // TODO: cache all of this, it shouldn't change often (if ever) and testDecrypt is slow
      try {
        const path = await this.lookupProfileHash({ publicKey });
        return await this.testDecryptAllSubscribers(path);
      } catch (err) {
        console.warn(`error decrypting subscriber stuff for pubkey: ${publicKey}`);
        throw err;
      }
    };

    // recursively gets links to all the posts for the given group, starting at `path`
    //    returning just the links is more useful because you can then resolve/load them lazily
    // note that it takes the true group secret key, not the group salt/name
    // salt in this case is for the posts, and may be different at different levels of recusion
    this.getPostLinks = async (groupKey, path, salt_ = undefined) => {
      let salt = salt_;
      const files = await ls(path)
        .then(flist => flist.map(f => f.name))
        .catch((err) => {
          if (err.message.includes('exist')) {
            // I think this should only happen if the profile in question has no /posts dir
            console.log("got this error in getPostLinks but we're handling it:", err.message);
            return [];
          }
          console.warn('unexpected error in getPostLinks');
          throw err;
        });
      let postList = [];
      if (files.includes('salt')) {
        salt = await cat(`${path}/salt`);
      }
      if (salt !== undefined) {
        // see if there are any posts for this group in there
        const name = hashfunc(uintConcat(salt, groupKey));
        if (files.includes(name)) {
          // a folder for this group! return a list of all the post dirs
          const posts = await ls(`${path}/${name}`)
            .then(flist => flist.map(f => f.name));
          postList = postList.concat(posts.map(p => `${path}/${name}/${p}`));
        }
      }
      // also try recursing deeper, but proactively ignore folders that definitely aren't dates
      const dirsToTry = files.filter(f => /^\d+$/g.test(f));
      const promises = dirsToTry.map(d => this.getPostLinks(groupKey, `${path}/${d}`, salt));
      postList = postList.concat((await Promise.all(promises)).flat());

      return postList;
    };

    this.getAllPostLinks = async (publicKey, groupSalt) => {
      const groupKey = this.getGroupKey(publicKey, groupSalt);
      const ipnsId = this.pubkeyToIpnsId(publicKey);

      // refresh latest profile version
      await this.lookupProfileHash({ publicKey });

      const path = `/ipns/${ipnsId}/posts`;
      return this.getPostLinks(await groupKey, path);
    };

    this.readPostMetadata = async (groupKey, path) =>
    // eslint-disable-next-line implicit-arrow-linebreak
      JSON.parse(await this.decrypt(groupKey, await cat(`${path}/meta.json`)));

    this.readPostData = async (groupKey, path) => {
      const files = await ls(path)
        .then(flist => flist.map(f => f.name).filter(f => !/^meta\.json/.test(f)));
      const mainName = files.filter(f => /^main\./.test(f))[0];
      if (mainName === undefined) {
        return undefined;
      }
      return (await this.decrypt(groupKey, await cat(`${path}/${mainName}`))).toString();
    };


    const setup = async () => {
      await this.ready;

      // Note: to start from scratch now you'll need to clear cookies too (because device keys)
      // node.files.rm('/posts', { recursive: true }).catch(() => {});
      // node.files.rm('/bio', { recursive: true }).catch(() => {});
      // node.files.rm('/groups', { recursive: true }).catch(() => {});
      // node.files.rm('/subscribers', { recursive: true }).catch(() => {});
      // node.files.rm('/private', { recursive: true }).catch(() => {});
      // node.files.rm('/device-keys', { recursive: true }).catch(() => {});

      // sanity check
      if ((await this.getIpnsId()) !== this.pubkeyToIpnsId(await this.getPublicKey())) {
        throw new Error('WATCH OUT! pubkeyToIpnsId IS OUT OF DATE');
      }

      // the other half of the IPNS setup
      // ingests get and post requests for IPNS records, responding to gets
      node.libp2p.handle('/gravity/0.0.1', (protocolName, connection) => {
        // this protocol, used here and in this.sendToPeer, has two possible message:
        // `g ${ipns ID}` - "please send me your best record for this ID (user)"
        // `p ${ipns record}` - any IPNS record (you're responsible for interpreting and validating)
        //      ^ that record is the libsodium base64 encoding of the libp2p protobuf
        pull(
          connection,
          pull.asyncMap(async (data, cb) => {
            if (LOG_MESSAGES) { console.log(`received: ${data.toString().slice(0, 12)}...`); }
            const split = data.toString().split(/\s+/);

            if (split[0] === 'p') { // post
              this.handlePost(split);
            } else if (split[0] === 'g') { // it's a get, need to respond
              // TODO: responding blindly reveals who we're friends with (by what's in the cache).
              //  maybe don't respond to all of them
              if (split[1] === (await this.getIpnsId())) {
                // if they're asking for mine, might as well give the most up to date answer
                await this.publishProfile([]);
              }
              if (split[1] in ipnsMap) {
                return cb(null, `p ${sodium.to_base64(ipns.marshal(ipnsMap[split[1]]))}`);
              }
            }

            return cb(null);
          }),
          pull.flatten(),
          connection,
        );
      });

      // load old records. better than nothing if the peer is offline
      try {
        ipnsMap = Object.assign(await getIpnsRecordStore(), ipnsMap);
      } catch (err) {
        console.warn('ipnsRecordStore load failed');
        console.error(err);
      }

      // set most up to date address
      // TODO: be more careful not to override other devices' addresses
      const info = await this.getNodeInfo();
      await this.setBio('public', { addresses: info.addresses });

      // await this.autoconnectPeers();
    };
    setup();
  }
}


module.exports = GravityProtocol;
