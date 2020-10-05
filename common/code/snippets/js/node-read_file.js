const {
  exec
} = require("child_process");

exec("cat /flag.txt", (error, stdout, stderr) => {
  console.log(`stdout: ${stdout}`);
});
