process.env["NODE_CONFIG_DIR"] = "./config/env";
const config = require('config');

export const configuration = () => ({
    ...config,
    ...process.env
});