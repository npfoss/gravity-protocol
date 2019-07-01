
const IPFS = require('ipfs');
const Cookies = require('js-cookie')

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
  })
    .catch(error => console.error(error));

  for (let i = 0; i < contents.length; i += 1) {
    const entry = contents[i];
    output[entry.name] = entry;

    if (entry.type === FILE_TYPES.DIRECTORY) {
      entry.contents = await loadDirs(ipfs, `${cleanpath}/${entry.name}`);
    }
  }

  return output;
};


//*  the protocol
class GravityProtocol {
  constructor() {
    const node = new IPFS();

    this.ready = false;

    node.on('ready', () => {
      // Ready to use!
      // See https://github.com/ipfs/js-ipfs#core-api

      this.ready = true;
    });

    this.loadDirs = async function (path) {
      if (!this.ready) {
        throw new Error("IPFS node isn't ready yet");
      }
      return loadDirs(node, path);
    };


    console.log(Cookies.set('test', 'success'))
    console.log(Cookies.get())
  }
}


module.exports = GravityProtocol;
