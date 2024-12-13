import { Body, Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './provider/auth.service';
import { LoginUserBodyDto } from './dto/login-user-body.dto';
import { SuccessResponse } from 'src/common/dto/success-response.dto';
import { ResponseMesages } from 'src/common/constants/response.messages';
import { RegisterUserBodyDto } from './dto/register-user-body.dto';
import { ResponseFormatterService } from 'src/common/helper_services/response_formatter.service';
import { UserEntity } from '../users/entity/user.entity';
import { SignupResponseSchema } from 'src/responseSchema/auth/signup.schema';
import { Public } from './decorators/public.decorator';
import { LoginResponseSchema } from 'src/responseSchema/auth/login.schema';
import { GetCurrentUser } from './decorators/get-current-user.decorator';
import { TokenGuard } from './guards/token.guard';
import { CurrentUserToken } from './decorators/current-user-token.decorator';
import { UserVerificationBodyDto } from './dto/user-verification.dto';
import { UserPasswordUpdateBodyDto } from './dto/reset-password-body.dto';
import { ResendVerificationBodyDto } from './dto/resend-verification.dto';
import { DualAuthVerificationBodyDto } from './dto/dual-auth-body.dto';

@Controller('auth')
@UseGuards(TokenGuard)
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly responseFormatterService: ResponseFormatterService,
  ) {}

  @Public()
  @Post('login')
  @Public()
  async login(@Body() body: LoginUserBodyDto): Promise<SuccessResponse> {
    const userDetail = await this.authService.login(body);
    const user = this.responseFormatterService.formatResponse(
      userDetail.user,
      LoginResponseSchema,
    );
    return new SuccessResponse(
      userDetail.isVerificationRequired
        ? ResponseMesages.VERIFICATION_REQUIRED
        : ResponseMesages.USER_LOGIN_SUCCESSFULLY,
      {
        user: user,
        isVerificationRequired: userDetail.isVerificationRequired,
        verificationToken: userDetail.verificationToken,
        token: userDetail.tokens,
      },
    );
  }

  @Public()
  @Post('signup')
  @Public()
  async signup(@Body() body: RegisterUserBodyDto): Promise<SuccessResponse> {
    let userDetail: Partial<UserEntity> | Partial<UserEntity>[] =
      await this.authService.createNewUser(body);
    userDetail = this.responseFormatterService.formatResponse(
      userDetail,
      SignupResponseSchema,
    );
    return new SuccessResponse(
      ResponseMesages.USER_REGISTER_SUCCESSFULLY,
      userDetail,
    );
  }

  @Patch('logout')
  async logout(
    @GetCurrentUser('sub') userID: string,
  ): Promise<SuccessResponse> {
    await this.authService.logout(userID);
    return new SuccessResponse(ResponseMesages.USER_LOGOUT_SUCCESSFULLY);
  }

  @Patch('refresh-token')
  async refreshToken(
    @GetCurrentUser('sub') user_id: string,
    @CurrentUserToken() token: string,
  ): Promise<SuccessResponse> {
    const tokenResponse = await this.authService.refreshTokens(user_id, token);
    return new SuccessResponse(ResponseMesages.TOKEN_REFRESHED_SUCCESSFULLY, {
      token: tokenResponse,
    });
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(
    @Body('userEmail') userEmail: string,
  ): Promise<SuccessResponse> {
    const forgotPasswordResponse =
      await this.authService.forgotPassword(userEmail);
    return new SuccessResponse(ResponseMesages.VERIFICATION_EMAIL_SENT, {
      user: forgotPasswordResponse,
    });
  }

  @Public()
  @Patch('reset-password')
  async resetPassword(
    @Body() reqBody: UserPasswordUpdateBodyDto,
  ): Promise<SuccessResponse> {
    this.authService.resetPassword(
      reqBody.user_id,
      reqBody.otp,
      reqBody.verification_token,
      reqBody.newPassword,
    );
    return new SuccessResponse(ResponseMesages.PASSWORD_RESET_SUCCESSFULLY);
  }

  @Public()
  @Post('verify-email')
  async verifyEmail(
    @Body() verification: UserVerificationBodyDto,
  ): Promise<SuccessResponse> {
    await this.authService.verifyUser(
      verification.user_id,
      verification.otp,
      verification.verification_token,
      verification.verification_type,
    );

    return new SuccessResponse(ResponseMesages.USER_VERIFIED_SUCCESSFULLY);
  }

  @Public()
  @Post('resend-verification-email')
  async resendVerificationEmail(
    @Body() reqBody: ResendVerificationBodyDto,
  ): Promise<SuccessResponse> {
    await this.authService.resendVerificationEmail(
      reqBody.user_id,
      reqBody.verification_type,
    );
    return new SuccessResponse(ResponseMesages.OTP_SENT_SUCCESSFULLY);
  }

  @Public()
  @Post('dual-auth')
  async dualAuth(
    @Body() dualAuthBody: DualAuthVerificationBodyDto,
  ): Promise<SuccessResponse> {
    const userDetail = await this.authService.validateDualAuth(dualAuthBody);
    return new SuccessResponse(ResponseMesages.USER_LOGIN_SUCCESSFULLY, {
      user: userDetail,
      isVerificationRequired: userDetail.isVerificationRequired,
      tokens: userDetail.tokens,
    });
  }
}
