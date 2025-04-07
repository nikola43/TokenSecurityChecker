// Token Security Checker
const { ethers } = require('ethers');
const fs = require('fs');
const cors = require("cors");
const express = require("express");
const axios = require('axios');

// Common ERC20 ABI, extended with ownership and security-related functions
const ERC20_ABI = [
    // Basic ERC20 functions
    'function name() view returns (string)',
    'function symbol() view returns (string)',
    'function decimals() view returns (uint8)',
    'function totalSupply() view returns (uint256)',
    'function balanceOf(address) view returns (uint256)',
    'function transfer(address to, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
    'function approve(address spender, uint256 amount) returns (bool)',
    'function transferFrom(address from, address to, uint256 amount) returns (bool)',
    // Ownership
    'function owner() view returns (address)',
    'function getOwner() view returns (address)',
    'function renounceOwnership() returns ()',
    'function transferOwnership(address newOwner) returns ()',
    // Extra functions that might be present
    'function mint(address to, uint256 amount) returns (bool)',
    'function burn(uint256 amount) returns (bool)',
    'function pause() returns (bool)',
    'function unpause() returns (bool)',
    'function paused() view returns (bool)',
    'function addToBlacklist(address account) returns (bool)',
    'function removeFromBlacklist(address account) returns (bool)',
    'function isBlacklisted(address account) view returns (bool)',
    'function addToWhitelist(address account) returns (bool)',
    'function removeFromWhitelist(address account) returns (bool)',
    'function isWhitelisted(address account) view returns (bool)',
    // Events
    'event Transfer(address indexed from, address indexed to, uint256 value)',
    'event Approval(address indexed owner, address indexed spender, uint256 value)',
    'event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)',
];

class TokenSecurityChecker {
    // explorerUrl = "https://api.scan.pulsechain.com/api/v2/smart-contracts/";
    explorerUrl = "https://api.scan.v4.testnet.pulsechain.com/api/v2/smart-contracts/";

    constructor(rpcUrl) {
        this.provider = new ethers.providers.JsonRpcProvider(rpcUrl);
        this.results = {};
        this.sourceCode = '';
    }

    async checkToken(tokenAddress) {
        console.log(`Analyzing token: ${tokenAddress}...`);

        const sourceCode = await this.getContractSourceCode(tokenAddress);
        this.sourceCode = sourceCode;



        try {
            // Initialize token contract
            this.tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, this.provider);

            // Get basic token info
            const [name, symbol, decimals, totalSupply] = await Promise.all([
                this.tokenContract.name().catch(() => 'Unknown'),
                this.tokenContract.symbol().catch(() => 'Unknown'),
                this.tokenContract.decimals().catch(() => 18),
                this.tokenContract.totalSupply().catch(() => '0'),
            ]);

            // Store results
            this.results = {
                tokenAddress,
                name,
                symbol,
                decimals: Number(decimals),
                totalSupply: ethers.utils.formatUnits(totalSupply, decimals),
                securityChecks: {}
            };

            // Perform all security checks
            await this.checkOwnership();
            await this.checkHiddenOwner();
            await this.checkHoneypot();
            await this.checkMintable();
            await this.checkProxyContract();
            await this.checkSuspiciousFunctions();
            await this.checkBlacklist();
            await this.checkWhitelist();
            await this.checkTransferCooldown();
            await this.checkTransferPausable();
            await this.checkPegRatio();

            return this.results;
        } catch (error) {
            console.error('Error checking token:', error);
            return { error: error.message };
        }
    }

    async getContractSourceCode(address) {
        const url = `${this.explorerUrl}/${address}`;

        try {
            const response = await fetch(url);
            const data = await response.json();
            // console.log(data.source_code);

            if (data && data.source_code && data.source_code.length > 0) {
                return data.source_code;
            }
            return null;
        } catch (error) {
            console.error('Error fetching source code:', error);
            return null;
        }
    }

    async checkOwnership() {
        try {
            // Try to call owner() function
            const ownerAddress = await this.tokenContract.owner().catch(() =>
                // Fallback to getOwner() if owner() doesn't exist
                this.tokenContract.getOwner().catch(() => null)
            );
            // console.log(ownerAddress);

            // If we can't get an owner address, ownership might be renounced
            // Or the contract doesn't implement Ownable pattern
            const ownershipRenounced =
                !ownerAddress ||
                ownerAddress === '0x0000000000000000000000000000000000000000';

            this.results.securityChecks.ownershipRenounced = ownershipRenounced;

            if (!ownershipRenounced && ownerAddress) {
                this.results.ownerAddress = ownerAddress;
            }
        } catch (error) {
            // If we can't detect ownership functions, we can't determine if renounced
            this.results.securityChecks.ownershipRenounced = false;
            this.results.securityChecks.ownershipDetectionError = error.message;
        }
    }

    async checkHiddenOwner() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.hiddenOwner = "Unknown - Source code not verified";
                return;
            }

            // Check for hidden ownership patterns in the source code
            const hiddenOwnerPatterns = [
                /onlyOwner\s*\{\s*if\s*\(msg\.sender\s*!=\s*([^)]+)\)/i,
                /require\s*\(\s*msg\.sender\s*==\s*([^)]+)\s*,/i,
                /selfdestruct\s*\(\s*payable\s*\(\s*([^)]+)\s*\)/i,
                /delegatecall\s*\(/i,
                /assembly\s*\{/i
            ];

            // Look for hidden backdoors or suspicious patterns
            const hasHiddenOwnerPatterns = hiddenOwnerPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.hiddenOwner = hasHiddenOwnerPatterns;
        } catch (error) {
            console.error('Error checking hidden owner:', error);
            this.results.securityChecks.hiddenOwner = "Unknown - Error analyzing source code";
        }
    }

    async checkHoneypot() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.honeypot = "Unknown - Source code not verified";
                return;
            }

            // Check for common honeypot patterns
            const honeypotPatterns = [
                /require\s*\(\s*balanceOf\s*\(\s*msg\.sender\s*\)\s*[<>=]=\s*[^)]+\s*\)/i,
                /require\s*\(\s*block\.timestamp\s*[<>=]=\s*[^)]+\s*\)/i,
                /require\s*\(\s*msg\.sender\s*==\s*tx\.origin\s*\)/i,
                /require\s*\(\s*_balances\s*\[\s*msg\.sender\s*\]\s*[<>=]=\s*[^)]+\s*\)/i,
                /require\s*\(\s*[^)]+\s*!=\s*address\s*\(\s*[^)]+\s*\)\s*\)/i,
                /tax|fee/i
            ];

            // Look for potential honeypot indicators
            const hasHoneypotPatterns = honeypotPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.honeypot = hasHoneypotPatterns;
        } catch (error) {
            console.error('Error checking honeypot:', error);
            this.results.securityChecks.honeypot = "Unknown - Error analyzing source code";
        }
    }

    async checkMintable() {
        try {
            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.mintable = "Unknown - Source code not verified";
                return;
            }

            // Check for mint function patterns
            const mintPatterns = [
                /function\s+mint\s*\(/i,
                /function\s+_mint\s*\(/i,
                /ERC20Mintable/i
            ];

            // Look for mintable function
            const hasMintableFunction = mintPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.mintable = hasMintableFunction;
        } catch (error) {
            console.error('Error checking mintable:', error);
            this.results.securityChecks.mintable = "Unknown - Error checking mintable";
        }
    }

    async checkProxyContract() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.proxyContract = "Unknown - Source code not verified";
                return;
            }

            // Check for proxy patterns
            const proxyPatterns = [
                /delegatecall\s*\(/i,
                /proxy/i,
                /upgradeable/i,
                /implementation\s*\(/i,
                /StorageSlot/i,
                /ERC1967Upgrade/i
            ];

            // Look for proxy implementation
            const isProxyContract = proxyPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.proxyContract = isProxyContract;
        } catch (error) {
            console.error('Error checking proxy contract:', error);
            this.results.securityChecks.proxyContract = "Unknown - Error checking proxy";
        }
    }

    async checkSuspiciousFunctions() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.hasSuspiciousFunctions = "Unknown - Source code not verified";
                return;
            }

            // Check for suspicious function patterns
            const suspiciousFunctionPatterns = [
                /selfdestruct\s*\(/i,
                /delegatecall\s*\(/i,
                /setTaxFeePercent/i,
                /setMaxTxAmount/i,
                /excludeFromFee/i,
                /setBlacklistEnabled/i,
                /setCanTransfer/i,
                /setRouterAddress/i,
                /setSwapEnabled/i,
                /updateFee/i
            ];

            // Look for suspicious functions
            const hasSuspiciousFunctions = suspiciousFunctionPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.hasSuspiciousFunctions = hasSuspiciousFunctions;
        } catch (error) {
            console.error('Error checking suspicious functions:', error);
            this.results.securityChecks.hasSuspiciousFunctions = "Unknown - Error checking suspicious functions";
        }
    }

    async checkBlacklist() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.hasBlacklist = "Unknown - Source code not verified";
                return;
            }

            // Check for blacklist patterns
            const blacklistPatterns = [
                /blacklist/i,
                /blocked/i,
                /banned/i,
                /isBlacklisted/i,
                /_blacklist/i,
                /blacklistAddress/i
            ];

            // Look for blacklist functions
            const hasBlacklist = blacklistPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.hasBlacklist = hasBlacklist;
        } catch (error) {
            console.error('Error checking blacklist:', error);
            this.results.securityChecks.hasBlacklist = "Unknown - Error checking blacklist";
        }
    }

    async checkWhitelist() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.hasWhitelist = "Unknown - Source code not verified";
                return;
            }

            // Check for whitelist patterns
            const whitelistPatterns = [
                /whitelist/i,
                /whitelisted/i,
                /isWhitelisted/i,
                /_whitelist/i,
                /whitelistAddress/i
            ];

            // Look for whitelist functions
            const hasWhitelist = whitelistPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.hasWhitelist = hasWhitelist;
        } catch (error) {
            console.error('Error checking whitelist:', error);
            this.results.securityChecks.hasWhitelist = "Unknown - Error checking whitelist";
        }
    }

    async checkTransferCooldown() {
        try {


            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.transferCooldown = "Unknown - Source code not verified";
                return;
            }

            // Check for cooldown patterns
            const cooldownPatterns = [
                /cooldown/i,
                /cooldownTime/i,
                /lockTime/i,
                /lastTrade/i,
                /block\.timestamp/i,
                /timeLimit/i,
                /tradingCooldown/i
            ];

            // Look for transfer cooldown mechanism
            const hasTransferCooldown = cooldownPatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.transferCooldown = hasTransferCooldown;
        } catch (error) {
            console.error('Error checking transfer cooldown:', error);
            this.results.securityChecks.transferCooldown = "Unknown - Error checking transfer cooldown";
        }
    }

    async checkTransferPausable() {
        try {
            // Try to call paused() function
            let isPaused = false;
            try {
                isPaused = await this.tokenContract.paused();
            } catch (error) {
                console.error('Error checking paused:', error);
                // Function doesn't exist or is not accessible
                isPaused = false;
            }



            if (!this.sourceCode || this.sourceCode.length === 0) {
                this.results.securityChecks.transferPausable = isPaused;
                return;
            }

            // Check for pausable patterns
            const pausablePatterns = [
                /Pausable/i,
                /paused\s*\(/i,
                /whenNotPaused/i,
                /pause\s*\(/i,
                /unpause\s*\(/i,
                /isPaused/i
            ];

            // Look for transfer pausable mechanism
            const hasTransferPausable = isPaused || pausablePatterns.some(
                pattern => pattern.test(this.sourceCode)
            );

            this.results.securityChecks.transferPausable = hasTransferPausable;
        } catch (error) {
            console.error('Error checking transfer pausable:', error);
            this.results.securityChecks.transferPausable = "Unknown - Error checking transfer pausable";
        }
    }

    formatResults() {
        console.log('\n=== TOKEN SECURITY ANALYSIS ===');
        console.log(`Token: ${this.results.name} (${this.results.symbol})`);
        console.log(`Address: ${this.results.tokenAddress}`);
        console.log(`Decimals: ${this.results.decimals}`);
        console.log(`Total Supply: ${this.results.totalSupply}`);
        console.log('\n=== SECURITY CHECKS ===');

        for (const [check, result] of Object.entries(this.results.securityChecks)) {
            const formattedCheck = check
                .replace(/([A-Z])/g, ' $1')
                .replace(/^./, str => str.toUpperCase());

            let icon, resultText;

            if (check === 'ownershipRenounced') {
                // For ownership renounced, "Yes" is good
                icon = result ? '✅' : '❌';
                resultText = result ? 'Yes' : 'No';
            } else if (check === 'hiddenOwner') {
                // For hidden owner, "No" is good
                icon = result ? '❌' : '✅';
                resultText = result ? 'Yes' : 'No';
            } else {
                // For all other checks, "No" is generally good
                icon = result ? '✅' : '✅';
                resultText = result ? 'Yes' : 'No';
            }

            console.log(`${formattedCheck}: ${icon} ${resultText}`);
        }
    }

    saveResultsToFile(filename) {
        fs.writeFileSync(
            filename,
            JSON.stringify(this.results, null, 2),
            'utf8'
        );
        console.log(`\nResults saved to ${filename}`);
    }

    checkPegRatio = async () => {
        const tokenAddress = this.results.tokenAddress;
        const tokenId = tokenAddress.toLowerCase();
        console.log(tokenId);

        const query = `
        query MyQuery {
            tokens(where: { id: "${tokenId}" }) {
            id
            symbol
            derivedUSD
            }
        }
    `;

        try {
            const response = await axios.post(
                'https://pdexsubgraph.9inch.io/subgraphs/name/exchange-v3',
                {
                    query,
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
            console.log(response.data.data.tokens[0]);


            const pegRatio = calculatePegRatio(Number(response.data.data.tokens[0].derivedUSD), 1)

            console.log(pegRatio);
            this.results.pegRatio = pegRatio.ratioFormat;
        } catch (error) {
            console.error('GraphQL query failed:', error);
            return null;
        }
    }
}

function calculatePegRatio(tokenValue, referenceValue) {
    // Calculate the basic ratio
    const ratio = tokenValue / referenceValue;

    // Calculate the percentage (ratio * 100)
    const percentageRatio = ratio * 100;

    // Calculate the ratio format
    let ratioFormatted;

    if (ratio < 1) {
        // Token trading below peg - show as 1:X format
        const inverseRatio = (1 / ratio).toFixed(0);
        ratioFormatted = `1:${inverseRatio}`;
    } else {
        // Token trading above peg - show as X:1 format
        const normalRatio = ratio.toFixed(0);
        ratioFormatted = `${normalRatio}:1`;
    }

    // Prepare the formatted values for output
    return {
        decimal: ratio,
        percentage: percentageRatio.toFixed(4) + '%',
        ratioFormat: ratioFormatted,
    };
}

// const rpcUrl = `https://rpc-pulsechain.g4mm4.io`;
const rpcUrl = `https://rpc-testnet-pulsechain.g4mm4.io`;
const app = express();
app.use(express.json()); // <==== parse request body as JSON
app.use(express.urlencoded({ extended: true }));
const provider = new ethers.providers.JsonRpcProvider(rpcUrl);

app.use(
    cors({
        //origin: 'https:website.com'
        origin: "*",
    })
);

app.get("/", async (req, res) => {
    res.send("api is running");
});

app.get("/audit", async (req, res) => {
    const tokenAddress = req.query.tokenAddress;


    // check if token address is provided
    if (!tokenAddress) {
        res.status(400).send("Token address is required");
        return
    }

    // check if token address is valid
    if (!ethers.utils.isAddress(tokenAddress)) {
        res.status(400).send("Invalid token address");
        return
    }

    // check if address is a contract
    const code = await provider.getCode(tokenAddress);
    if (code === "0x") {
        res.status(400).send("Invalid address is not a contract");
        return
    }

    const checker = new TokenSecurityChecker(rpcUrl);
    const result = await checker.checkToken(tokenAddress);
    res.send(result);
})

app.listen(1234, () => {
    console.log(`Example app listening on port ${1234}`)
})