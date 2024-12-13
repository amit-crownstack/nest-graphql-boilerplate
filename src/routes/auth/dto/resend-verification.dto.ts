import { IsNotEmpty, IsString } from 'class-validator';

export class ResendVerificationBodyDto {
  @IsNotEmpty()
  @IsString()
  user_id: string;

  @IsNotEmpty()
  @IsString()
  verification_type: string;
}
