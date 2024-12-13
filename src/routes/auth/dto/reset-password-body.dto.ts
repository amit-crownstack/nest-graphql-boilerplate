import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class UserPasswordUpdateBodyDto {
  @IsNotEmpty()
  @IsString()
  user_id: string;

  @IsNotEmpty()
  @IsString()
  verification_token: string;

  @IsNotEmpty()
  otp: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/,
    {
      message:
        'Password must include at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 special character',
    },
  )
  newPassword: string;
}
