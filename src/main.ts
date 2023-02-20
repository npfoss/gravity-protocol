const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

console.log("1");
sleep(100).then(() => console.log(2));
