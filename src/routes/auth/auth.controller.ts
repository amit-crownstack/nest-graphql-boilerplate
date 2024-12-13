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

  /**
   * @api {post} /auth/login User Login
   * @apiDescription Login a user using email and password
   * @apiBody {Object} LoginUserBodyDto - Contains email and password
   * @apiSuccess {Object} user - User details
   * @apiSuccess {Boolean} isVerificationRequired - If verification is needed
   * @apiSuccess {String} token - Access token
   */
  @Public()
  @Post('login')
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

  /**
   * @api {post} /auth/signup User Registration
   * @apiDescription Register a new user
   * @apiBody {Object} RegisterUserBodyDto - User registration data
   * @apiSuccess {Object} user - Newly created user details
   */
  @Public()
  @Post('signup')
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

  /**
   * @api {patch} /auth/logout User Logout
   * @apiDescription Logs out the current user
   * @apiHeader {String} Authorization - User's access token
   * @apiSuccess {String} message - Logout success message
   */
  @Patch('logout')
  async logout(
    @GetCurrentUser('sub') userID: string,
  ): Promise<SuccessResponse> {
    await this.authService.logout(userID);
    return new SuccessResponse(ResponseMesages.USER_LOGOUT_SUCCESSFULLY);
  }

  /**
   * @api {patch} /auth/refresh-token Refresh Token
   * @apiDescription Refreshes the access token
   * @apiHeader {String} Authorization - Refresh token
   * @apiSuccess {Object} tokens - New access and refresh tokens
   */
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

  /**
   * @api {post} /auth/forgot-password Forgot Password
   * @apiDescription Sends a password reset email to the user
   * @apiBody {String} userEmail - User's email address
   * @apiSuccess {String} message - Email sent success message
   */
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

  /**
   * @api {patch} /auth/reset-password Reset Password
   * @apiDescription Resets the user's password
   * @apiBody {Object} UserPasswordUpdateBodyDto - Reset password data
   * @apiSuccess {String} message - Password reset success message
   */
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

  /**
   * @api {post} /auth/verify-email Verify Email
   * @apiDescription Verifies the user's email address
   * @apiBody {Object} UserVerificationBodyDto - Verification details
   * @apiSuccess {String} message - Verification success message
   */
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

  /**
   * @api {post} /auth/resend-verification-email Resend Verification Email
   * @apiDescription Resends the verification email to the user
   * @apiBody {Object} ResendVerificationBodyDto - User ID and verification type
   * @apiSuccess {String} message - OTP sent success message
   */
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

  /**
   * @api {post} /auth/dual-auth Dual Authentication
   * @apiDescription Validates dual authentication for a user
   * @apiBody {Object} DualAuthVerificationBodyDto - Dual auth details
   * @apiSuccess {Object} user - User details
   * @apiSuccess {Object} tokens - Access tokens
   */
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
