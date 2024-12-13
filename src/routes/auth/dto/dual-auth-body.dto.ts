import { IsNotEmpty, IsString } from 'class-validator';

export class DualAuthVerificationBodyDto {
  @IsNotEmpty()
  @IsString()
  user_id: string;

  @IsNotEmpty()
  @IsString()
  verification_token: string;

  @IsNotEmpty()
  otp: string;
}
