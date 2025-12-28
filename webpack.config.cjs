const path = require('path');
const WebpackObfuscator = require('webpack-obfuscator');

module.exports = {
    entry: './public/js/modules/main.js', // Entry point
    output: {
        filename: 'bundle.js', // Output file
        path: path.resolve(__dirname, 'public/js/dist'), // Output directory
        clean: true, // Clean the output directory before emit
    },
    mode: 'production', // Optimization for production
    plugins: [
        new WebpackObfuscator({
            rotateStringArray: true,
            stringArray: true,
            stringArrayThreshold: 0.75, // Higher = more obfuscation
            compact: true,
            controlFlowFlattening: true,
            controlFlowFlatteningThreshold: 0.75,
            deadCodeInjection: true,
            deadCodeInjectionThreshold: 0.4,
            debugProtection: true,
            debugProtectionInterval: 2000, // Makes debugging annoying
            disableConsoleOutput: true, // Hides console.logs (optional, good for security)
            identifierNamesGenerator: 'hexadecimal',
            log: false,
            renameGlobals: false,
            selfDefending: true, // Makes code break if formatted/beautified
            splitStrings: true,
            splitStringsChunkLength: 10,
        }, [])
    ],
    optimization: {
        minimize: true
    }
};
