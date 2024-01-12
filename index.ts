import { randomUUID } from 'node:crypto'
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import express, { json } from 'express'
import session from 'express-session'
import RedisStore from 'connect-redis'
import Redis from 'ioredis'
import type { AuthenticationResponseJSON, AuthenticatorDevice, AuthenticatorTransportFuture, RegistrationResponseJSON } from '@simplewebauthn/typescript-types'
import { PrismaClient } from '@prisma/client'

const redis = new Redis()

const redisStore = new RedisStore({
	client: redis,
	prefix: 'webauthn',
})

const prisma = new PrismaClient()

const app = express()
const port = 8080

const rpID = 'localhost'

app.use(json())
app.use(session({
	secret: 'webauthn-example-app',
	store: redisStore,
	resave: false,
	saveUninitialized: false,
	cookie: {
		maxAge: 86400000,
	},
}))

app.use('/', express.static('html'))

app.post('/register/option', async (req, res) => {
	const username = req.body.username as string

	const user = await prisma.user.findFirst({ where: { username }, include: { device: { include: { transports: true } } } })

	const devices: AuthenticatorDevice[] = user?.device ?
		user.device.map(device => ({
			counter: device.counter,
			credentialID: isoBase64URL.toBuffer(device.credentialID),
			credentialPublicKey: isoBase64URL.toBuffer(device.credentialPublicKey),
			transports: device.transports.map(transport => transport.type as AuthenticatorTransportFuture),
		})) :
		[]
	const uuid = randomUUID()

	const opts = await generateRegistrationOptions({
		rpName: 'Ayaka\'s Clubhouse',
		rpID,
		userID: uuid,
		userName: username,
		userDisplayName: username,
		timeout: 60 * 1000,
		attestationType: 'none', // rp 是否向 authenticator 索要证明
		authenticatorSelection: {
			residentKey: 'discouraged', // 是否创建客户端凭证
		},
		excludeCredentials: devices.map(dev => ({ // 排除用户已经注册的 authenticator
			id: dev.credentialID,
			type: 'public-key',
			transport: dev.transports,
		})),
		supportedAlgorithmIDs: [-7, -257], // 支持的加密算法
	})

	req.session.challenge = opts.challenge
	req.session.user = user ?? undefined
	req.session.username = username
	console.log('session', req.session)

	res.json(opts)
})

app.post('/register/verify', async (req, res) => {
	const body: RegistrationResponseJSON = req.body
	const user = req.session.user
	const username = req.session.username
	const challenge = req.session.challenge
	if (!challenge || !username) {
		return res.status(400).send({ error: 'session not valid' })
	}
	let newUser
	const verification = await verifyRegistrationResponse({
		response: body,
		expectedChallenge: challenge,
		expectedOrigin: false ? `http://${rpID}` : `http://${rpID}:${port}`,
		expectedRPID: rpID,
		requireUserVerification: false, // 要求验证用户
	})
	const { verified, registrationInfo } = verification
	if (verification && registrationInfo) {
		const { credentialPublicKey, credentialID, counter } = registrationInfo
		const credentialIDHex = isoBase64URL.fromBuffer(credentialID)

		const existingDevice = user?.device?.find(device => device.credentialID === credentialIDHex)
		// ensure duplicate devices are not added
		if (!existingDevice) {
			await prisma.$transaction(async (tx) => {
				// if user is unregistered, create a new user
				if (!user) {
					newUser = await tx.user.create({ data: { username } })
				}

				// add device to database
				const device = await tx.device.create({
					data: {
						credentialID: isoBase64URL.fromBuffer(credentialID),
						credentialPublicKey: isoBase64URL.fromBuffer(credentialPublicKey),
						counter,
						userId: user?.id ?? newUser!.id,
					},
				})

				// save transports
				// `createMany` is not supported on SQLite which is the datasource of this demo,
				// could use `createMany` instead in the production environment using other datasource
				if (body.response.transports) {
					for (const transport of body.response.transports) {
						await tx.authenticatorTransports.create({ data: { type: transport, deviceId: device.id } })
					}
				}
			})
		}
	}

	req.session.challenge = undefined
	req.session.user = undefined

	if (verified) {
		req.session.loggedUserId = user?.id ?? newUser!.id
	}

	res.send({ verified })
})

app.post('/login/option', async (req, res) => {
	const username = req.body.username as string
	let user
	if (username) {
		user = await prisma.user.findFirst({ where: { username }, include: { device: { include: { transports: true } } } })
		console.log(username, user)
		if (!user) {
			return res.status(400).send({ error: 'user not exists' })
		}
	}
	const opts = await generateAuthenticationOptions({
		userVerification: 'discouraged',
		rpID,
		timeout: 60 * 1000,
		allowCredentials: user ?
			user.device.map(device => ({
				id: isoBase64URL.toBuffer(device.credentialID),
				type: 'public-key',
				transports: device.transports.map(transport => transport.type as AuthenticatorTransportFuture),
			})) :
			[],

	})
	req.session.challenge = opts.challenge
	res.send(opts)
})

app.post('/login/verify', async (req, res) => {
	const body: AuthenticationResponseJSON = req.body
	const challenge = req.session.challenge
	if (!challenge || !body.rawId) {
		return res.status(400).send({ error: 'session not valid' })
	}
	const authenticator = await prisma.device.findFirst({ where: { credentialID: body.rawId }, include: { transports: true } })
	console.log('authenticator', authenticator)
	if (!authenticator) {
		return res.status(400).send({ error: 'This authenticator is not registered' })
	}

	const verification = await verifyAuthenticationResponse({
		response: body,
		requireUserVerification: false,
		expectedChallenge: challenge,
		expectedOrigin: false ? `http://${rpID}` : `http://${rpID}:${port}`,
		expectedRPID: rpID,
		authenticator: {
			credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
			credentialPublicKey: isoBase64URL.toBuffer(authenticator.credentialPublicKey),
			counter: authenticator.counter,
			transports: authenticator.transports.map(transport => transport.type as AuthenticatorTransportFuture),
		},
	})

	const { verified, authenticationInfo } = verification
	if (verified) {
		const device = await prisma.device.update({ where: { id: authenticator.id }, data: { counter: authenticationInfo.newCounter } })
		const user = await prisma.user.findFirst({ where: { id: device.userId } })
		req.session.loggedUserId = user?.id
	}

	req.session.challenge = undefined

	res.send({ verified })
})

app.all('/logout', (req, res) => {
	req.session.loggedUserId = undefined
	return res.send('You are logged out')
})

app.get('/whoami', async (req, res) => {
	const userId = req.session.loggedUserId
	if (!userId) {
		return res.send('You are not logged in')
	}
	const user = await prisma.user.findFirst({ where: { id: userId } })
	res.send(`You were logged as ${user?.username}(${user?.id})`)
})

app.listen(port, () => {
	console.log(`Listen on http://localhost:${port}`)
})
