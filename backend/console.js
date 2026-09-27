/**
 * AuthShield 360 - Console logging (banner + leveled lines), ASCII only.
 */
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const MAGENTA = '\x1b[35m';

export const log = {
    banner() {
        console.log(MAGENTA + `
   ___     _   _   ___  ____   __  __  _____  ___  _____  ___  ___  ___  ____
  / _ \\  | | | | / ___|| _ \\  \\ \\/ / / _ \\ \\| |\\ \\ |  _  || __||   ||    \\
 | |_| | | |_| | \\___ \\|   /   \\  /  | |_| |\` | | |') ||   _)|| |_ | |) || |) |
  \\___/  |_| |_| |_____||_|_\\    \\/    \\___/ |  |_|\\__ || |\\_|||_|  |___/ |_|_/
                                       |_|    |_|          |_|    USEC      |_|
` + RESET + CYAN + 'AuthShield 360 - Adaptive Identity Defense Platform\n' + DIM + 'node ' + process.version + RESET);
    },
    start(port) {
        console.log(GREEN + '[boot]  OK  listening on http://localhost:' + port + RESET + DIM + '  (launch dashboard to begin)' + RESET);
    },
    http(line) { console.log(DIM + '[http] ' + line + RESET); },
    info(line) { console.log(CYAN + '[info] ' + line + RESET); },
    warn(line) { console.log(YELLOW + '[warn] ' + line + RESET); },
    error(line) { console.error(RED + '[error] ' + line + RESET); },
};