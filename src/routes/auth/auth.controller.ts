import { Body, Controller, Patch, Post } from '@nestjs/common';
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

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly responseFormatterService: ResponseFormatterService,
  ) {}

  @Post('login')
  @Public()
  async login(@Body() body: LoginUserBodyDto): Promise<SuccessResponse> {
    const userDetail = await this.authService.login(body);
    const user = this.responseFormatterService.formatResponse(
      userDetail.user,
      LoginResponseSchema,
    );
    return new SuccessResponse(ResponseMesages.USER_LOGIN_SUCCESSFULLY, {
      user: user,
      token: userDetail.tokens,
    });
  }

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
  async refreshToken(): Promise<any> {
    return {
      message: 'Refresh token successfully',
    };
  }

  @Post('forgot-password')
  async forgotPassword(): Promise<any> {
    return {
      message: 'Forgot password successfully',
    };
  }

  @Patch('reset-password')
  async resetPassword(): Promise<any> {
    return {
      message: 'Reset password successfully',
    };
  }

  @Post('verify-email')
  async verifyEmail(): Promise<any> {
    return {
      message: 'Verify email successfully',
    };
  }

  @Post('resend-verification-email')
  async resendVerificationEmail(): Promise<any> {
    return {
      message: 'Resend verification email successfully',
    };
  }

  @Post('dual-auth')
  async dualAuth(): Promise<any> {
    return {
      message: 'Dual auth successfully',
    };
  }
}
