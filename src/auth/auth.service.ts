import {
	BadRequestException,
	Injectable,
	NotFoundException,
	UnauthorizedException
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { User } from '@prisma/client'
import { verify } from 'argon2'
import { Response } from 'express'
import { UserService } from 'src/user/user.service'
import { AuthDto } from './dto/auth.dto'
import { RefreshTokenDto } from './dto/refresh-token.dto'

@Injectable()
export class AuthService {
	EXPIRE_DAY_REFRESH_TOKEN = 1
	REFRESH_TOKEN_NAME = 'refreshToken'

	constructor(private jwt: JwtService, private userService: UserService) {}

	// async login(dto: AuthDto) {
	// 	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	// 	const { password, ...user } = await this.validateUser(dto)
	// 	const tokens = this.issueTokens(user.id)

	// 	return {
	// 		user,
	// 		...tokens
	// 	}
	// }

	async login(dto: AuthDto) {
		const user = await this.validateUser(dto)

		const tokens = await this.issueTokenPair(user.id)

		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	// async register(dto: AuthDto) {
	// 	const oldUser = await this.userService.getByEmail(dto.email)

	// 	if (oldUser) throw new BadRequestException('User already exists')

	// 	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	// 	const { password, ...user } = await this.userService.create(dto)

	// 	const tokens = this.issueTokens(user.id)

	// 	return {
	// 		user,
	// 		...tokens
	// 	}
	// }

	async register(dto: AuthDto) {
		const oldUser = await this.userService.getByEmail(dto.email)

		if (oldUser) throw new BadRequestException('User already exists')
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { ...user } = await this.userService.create(dto)

		const tokens = await this.issueTokenPair(user.id)

		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	// async getNewTokens(refreshToken: string) {
	// 	const result = await this.jwt.verifyAsync(refreshToken)
	// 	if (!result) throw new UnauthorizedException('Invalid refresh token')

	// 	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	// 	const { password, ...user } = await this.userService.getById(result.id)

	// 	const tokens = this.issueTokens(user.id)

	// 	return {
	// 		user,
	// 		...tokens
	// 	}
	// }

	async getNewTokens({ refreshToken }: RefreshTokenDto) {
		if (!refreshToken)
			throw new UnauthorizedException('Please, sign in to account')

		const result = await this.jwt.verifyAsync(refreshToken)
		if (!result) throw new UnauthorizedException('Invalid token or expired')

		//eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { ...user } = await this.userService.getById(result.id)

		const tokens = await this.issueTokenPair(user.id)

		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	// private issueTokens(userId: string) {
	// 	const data = { id: userId }

	// 	const accessToken = this.jwt.sign(data, {
	// 		expiresIn: '1h'
	// 	})

	// 	const refreshToken = this.jwt.sign(data, {
	// 		expiresIn: '7d'
	// 	})

	// 	return { accessToken, refreshToken }
	// }

	async issueTokenPair(userId: string) {
		const data = { id: userId }

		const refreshToken = await this.jwt.signAsync(data, {
			expiresIn: '15d'
		})

		const accessToken = await this.jwt.signAsync(data, {
			expiresIn: '91d'
		})

		return { accessToken, refreshToken }
	}

	private async validateUser(dto: AuthDto) {
		const user = await this.userService.getByEmail(dto.email)

		if (!user) throw new NotFoundException('User not found')

		const isValid = await verify(user.password, dto.password)

		if (!isValid) throw new UnauthorizedException('Invalid password')

		return user
	}

	addRefreshTokenToResponse(res: Response, refreshToken: string) {
		const expiresIn = new Date()
		expiresIn.setDate(expiresIn.getDate() + this.EXPIRE_DAY_REFRESH_TOKEN)

		res.cookie(this.REFRESH_TOKEN_NAME, refreshToken, {
			httpOnly: true,
			domain: 'localhost',
			expires: expiresIn,
			secure: true,
			// lax if production
			sameSite: 'none'
		})
	}

	returnUserFields(user: User) {
		return {
			id: user.id,
			createdAt: user.createdAt,
			updatedAt: user.updatedAt,
			email: user.email,
			name: user.name,
			workInterval: user.workInterval,
			breakInterval: user.breakInterval,
			intervalsCount: user.intervalsCount
		}
	}

	removeRefreshTokenFromResponse(res: Response) {
		res.cookie(this.REFRESH_TOKEN_NAME, '', {
			httpOnly: true,
			domain: 'localhost',
			expires: new Date(0),
			secure: true,
			// lax if production
			sameSite: 'none'
		})
	}
}
