const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const app = express();
app.use(bodyParser.json());
app.use(cors());

let users = {};

const rpName = 'PasskeyTest';
const rpID = 'localhost';
const origin = `http://${rpID}:3001`;

app.post('/generate-registration-options', async (req, res) => {
    const { username } = req.body;
    const options = await generateRegistrationOptions({ rpName: rpName, rpID: rpID, userID: isoUint8Array.fromUTF8String(username), userName: username });
    console.log(options)
    users[username] = { id: options.user.id, challenge: options.challenge };
    res.json(options);
});

app.post('/verify-registration', async (req, res) => {
    const { username, attestationResponse } = req.body;
    const user = users[username];
    console.debug(user)
    console.debug(attestationResponse)
    try {
        const verification = await verifyRegistrationResponse(
            {
                response: attestationResponse,
                expectedChallenge: user.challenge,
                expectedOrigin: origin,
                expectedRPID: rpID
            }
        );
        if (verification.verified) {
            user.credential = verification.registrationInfo;
            res.json({ verified: true });
        } else {
            res.json({ verified: false });
        }
    } catch (err) {
        console.log(err)
    }
});

app.post('/generate-authentication-options', async (req, res) => {
    const { username } = req.body;
    const user = users[username];
    if (!user || !user.credential) {
        return res.status(400).json({ error: 'User not registered' });
    }
    const options = await generateAuthenticationOptions({ rpID: rpID, allowCredentials: [{ id: user.credential.credentialID, type: 'public-key' }] });
    user.challenge = options.challenge;
    res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
    const { username, assertionResponse } = req.body;
    const user = users[username];
    console.debug(user)
    const verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: user.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: {
            ...user.credential
        }
    });
    res.json({ verified: verification.verified });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
