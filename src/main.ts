import { create as createIpfsNode, IPFS } from "ipfs-core";

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

console.log("1");
sleep(100).then(() => console.log(2));

export class DynamicID {
  ipfs?: Promise<IPFS>;

  constructor(options = { noIPFS: false }) {
    if (!options.noIPFS) {
      this.ipfs = createIpfsNode();
    }
  }
}

(async () => {
  const did = new DynamicID();

  console.log((await did.ipfs)?.cat("QmPChd2hVbrJ6bfo3WBcTW4iZnpHm8TEzWkLHmLpXhF68A"));
})();
