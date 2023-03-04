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
  const ipfs = await did.ipfs;
  if (!ipfs) return;

  setInterval(async () => {
    console.log("peers:", (await ipfs.swarm.peers()).length);
  }, 5000);

  await sleep(5000);

  const itr = ipfs.cat("QmPChd2hVbrJ6bfo3WBcTW4iZnpHm8TEzWkLHmLpXhF68A");
  for await (const chunk of itr) {
    console.info(chunk);
  }
  console.log("next part");
  const cid = (await ipfs.dag.resolve("QmPChd2hVbrJ6bfo3WBcTW4iZnpHm8TEzWkLHmLpXhF68A")).cid;
  console.log(cid);
  console.log(await ipfs.dag.get(cid));
})();

//

// note for later: ipfs.resolve exists

/* some notes

extremely useful: current state: https://blog.ipfs.tech/state-of-ipfs-in-js/
js-ipfs is not really a full impl. it doesn't actually do retrieval and stuff itself, it depends on PL-run full nodes even to fetch content for them
even with new transports and stuff, still going to need a preload node to help them out (I guess it'll just be a little easier to run such a node?)
they're shutting down all the preload nodes, gotta do this yourself now



on preload: https://github.com/ipfs/js-ipfs/issues/3510
if a boostrap node doesn't have a file you have to ask the DHT who has it and connect to them
but browsers can't dial tcp, only websocket, not many nodes support this
so preload nodes will do that for you instead since you probably can't connect to the host that has the stuff
it's pretty costly and inefficient for the helper node
they're shutting this down



iroh: rust impl, focus on perf, also mobile?
https://github.com/n0-computer/iroh


use this instead of ipfs-http-client: https://github.com/ipfs/js-kubo-rpc-client
(to be a lite client for a full go node)


 */
