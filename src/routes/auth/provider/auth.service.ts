import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from 'src/routes/users/entity/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { LoginUserBodyDto } from '../dto/login-user-body.dto';
import { RegisterUserBodyDto } from '../dto/register-user-body.dto';
import { UsersService } from 'src/routes/users/provider/user.service';
import { ResponseMesages } from 'src/common/constants/response.messages';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from '../interfaces/tokens.interface';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private readonly userservice: UsersService,
    private jwtService: JwtService,
  ) {}

  /**
   *
   * @param userDetail
   * @returns userDetail
   */
  async login(
    userDetail: LoginUserBodyDto,
  ): Promise<{ user: UserEntity; tokens?: Tokens }> {
    // VALIDATE IF USER EXISTS
    const user = await this.userservice.getUserDetailByEmail(
      userDetail.userEmail,
    );
    if (!user) {
      throw new BadRequestException(ResponseMesages.EMAIL_NOT_FOUND);
    }
    // VALIDATE IF USER IS VERIFIED
    if (user.isrestricted) {
      throw new BadRequestException(ResponseMesages.USER_RESTRICTED);
    }

    // VALIDATE IF PASSWORD IS CORRECT
    if (!(await bcrypt.compare(userDetail.userPassword, user.userpassword))) {
      throw new BadRequestException(ResponseMesages.WRONG_CREDENTIALS);
    }

    // VALIDATE IF USER IS ACTIVE
    if (!user.verified) {
      // TODO: Send OTP to user's email
      return { user: user };
    } else {
      // VALIDATE IF DUAL AUTH IS ACTIVE
      if (user.dual_auth) {
        // TODO: Send OTP to user's email
        return { user: user };
      } else {
        // ALLOW USER TO LOGIN WITH ACCESS TOKEN AND REFRESH TOKEN
        const tokens = await this.generateTokens(user);
        await this.updateRefreshTokenHash(user.id, tokens.refreshToken);
        console.log({ user: user, tokens: tokens });

        return { user: user, tokens: tokens };
      }
    }
  }

  async createNewUser(userDetail: RegisterUserBodyDto): Promise<UserEntity> {
    if (await this.userservice.getUserDetailByEmail(userDetail.userEmail)) {
      throw new BadRequestException(ResponseMesages.EMAIL_ALREADY_EXISTS);
    }
    let user = this.userRepository.create({
      useremail: userDetail.userEmail,
      userpassword: userDetail.userPassword,
      phonenumber: userDetail.phoneNumber,
      countrycode: userDetail.countryCode,
    });
    user = await this.userRepository.save(user);
    // TODO: send OTP to user's email for email verification
    return user;
  }

  async refreshTokens(userId: string, refreshToken: string): Promise<Tokens> {
    const userSession = await this.userservice.findSessionById(userId);
    const user = await this.userservice.findUserById(userId);
    if (!userSession || !userSession.refreshToken)
      throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      userSession.refreshToken,
    );
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.generateTokens(user);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);
    return tokens;
  }

  private async generateTokens(user: UserEntity): Promise<Tokens> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.useremail,
      role: user.user_role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.JWT_SECRET_KEY,
        expiresIn: process.env.JWT_EXPIRY_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.JWT_REFRESH_SECRET_KEY,
        expiresIn: process.env.JWT_REFRESH_EXPIRY_TIME,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private async updateRefreshTokenHash(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.userservice.updateRefreshToken(userId, hashedToken);
  }

  async logout(userId: string): Promise<void> {
    await this.userservice.updateRefreshToken(userId, null);
  }
}
