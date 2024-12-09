import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
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
import { generateOTP } from 'src/common/helper/helper';
import { UserVerificationEntity } from '../entity/user_verification.entity';
import { VerificationStatus } from '../entity/enum/verification-status.enum';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    @InjectRepository(UserVerificationEntity)
    private userVerificationRepository: Repository<UserVerificationEntity>,
    private readonly userservice: UsersService,
    private jwtService: JwtService,
  ) {}

  /**
   *
   * @param userDetail
   * @returns userDetail
   */
  async login(userDetail: LoginUserBodyDto): Promise<{
    user: UserEntity;
    isVerificationRequired: boolean;
    verificationToken?: string;
    tokens?: Tokens;
  }> {
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
      const verificationUrlEncyptedKey =
        await this.createVerificationToken(user);
      //SAVE RECORD IN USER VERIFICATION TABLE
      await this.createVerificationRecord(
        user.id,
        verificationUrlEncyptedKey.otp,
        verificationUrlEncyptedKey.key,
        'EMAIL_VERIFICATION',
      );

      return {
        user: user,
        isVerificationRequired: true,
        verificationToken: verificationUrlEncyptedKey.key,
      };
    } else {
      // VALIDATE IF DUAL AUTH IS ACTIVE
      if (user.dual_auth) {
        // TODO: Send OTP to user's email
        const verificationUrlEncyptedKey =
          await this.createVerificationToken(user);
        //SAVE RECORD IN USER VERIFICATION TABLE
        await this.createVerificationRecord(
          user.id,
          verificationUrlEncyptedKey.otp,
          verificationUrlEncyptedKey.key,
          'TWO_FACTOR_AUTH',
        );

        return {
          user: user,
          isVerificationRequired: true,
          verificationToken: verificationUrlEncyptedKey.key,
        };
      } else {
        // ALLOW USER TO LOGIN WITH ACCESS TOKEN AND REFRESH TOKEN
        const tokens = await this.generateTokens(user);
        await this.updateRefreshTokenHash(user.id, tokens.refreshToken);
        return { user: user, isVerificationRequired: false, tokens: tokens };
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

  async createVerificationRecord(
    userId: string,
    otp: string,
    encryptionKey: string,
    verififcationType: string,
  ): Promise<void> {
    // TODO: Create a verification record in table user_verification
    const currentDate = new Date();
    const verificationRecord = this.userVerificationRepository.create({
      user_id: userId,
      verificationType: verififcationType,
      otpSecret: otp,
      token: encryptionKey,
      expiresAt: new Date(currentDate.getTime() + 10 * 60 * 1000),
    });
    await this.userVerificationRepository.save(verificationRecord);
  }

  async createVerificationToken(
    user: UserEntity,
  ): Promise<{ otp: string; key: string }> {
    const newOTP = generateOTP();
    const verificationUrlEncyptedKey = await this.jwtService.signAsync(
      {
        email: user.useremail,
        userID: user.id,
        otp: newOTP,
      },
      {
        secret: process.env.JWT_RESET_PASSWORD_SECRET_KEY,
        expiresIn: process.env.JWT_RESET_PASSWORD_EXPIRY_TIME,
      },
    );
    const hashedToken = await bcrypt.hash(verificationUrlEncyptedKey, 10);
    hashedToken.replace(/[/\\]/g, '');
    return { otp: newOTP, key: hashedToken };
  }

  async verifyUser(
    userID: string,
    otp: string,
    urlKey: string,
    verificationType: string,
  ): Promise<void> {
    const verificationRecord = await this.userVerificationRepository.findOne({
      where: { user_id: userID },
    });
    if (!verificationRecord) {
      throw new NotFoundException(ResponseMesages.USER_NOT_FOUND);
    }
    const currentDate = new Date();
    if (verificationRecord.expiresAt < currentDate) {
      await this.updateVeificationStatus(
        userID,
        verificationType,
        VerificationStatus.EXPIRED,
      );
      throw new BadRequestException(ResponseMesages.VERIFICATION_EXPIRED);
    }

    if (verificationRecord.token !== urlKey) {
      await this.updateVeificationStatus(
        userID,
        verificationType,
        VerificationStatus.FAILED,
      );
      throw new BadRequestException(ResponseMesages.INVALID_URL);
    }

    if (verificationRecord.verificationType === 'EMAIL_VERIFICATION') {
      if (verificationRecord.otpSecret !== otp) {
        throw new BadRequestException(ResponseMesages.WRONG_OTP);
      }
    }

    await this.updateVeificationStatus(
      userID,
      verificationType,
      VerificationStatus.COMPLETED,
    );
  }

  async updateVeificationStatus(
    userID: string,
    verificationType: string,
    status: VerificationStatus,
  ): Promise<void> {
    await this.userVerificationRepository.update(
      {
        user_id: userID,
        verificationType: verificationType,
        status: VerificationStatus.PENDING,
      },
      { status: status },
    );
  }
}
