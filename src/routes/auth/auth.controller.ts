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

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly responseFormatterService: ResponseFormatterService,
  ) {}

  @Post('login')
  async login(@Body() body: LoginUserBodyDto): Promise<SuccessResponse> {
    const userDetail = await this.authService.login(body);
    return new SuccessResponse(
      ResponseMesages.USER_LOGIN_SUCCESSFULLY,
      userDetail,
    );
  }

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

  @Patch('logout')
  async logout(): Promise<any> {
    return {
      message: 'Logout successfully',
    };
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
