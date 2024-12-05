import { IsNotEmpty, IsString, Matches } from 'class-validator';
import { LoginUserBodyDto } from './login-user-body.dto';

export class RegisterUserBodyDto extends LoginUserBodyDto {
  @IsString()
  @IsNotEmpty({ message: 'Country code is required' })
  @Matches(/^\+[1-9]\d{1,14}$/, {
    message: 'Invalid country code. Must start with + and be 1-15 digits long',
  })
  countryCode: string;

  @IsString()
  @IsNotEmpty({ message: 'Phone number is required' })
  @Matches(/^[0-9]{10}$/, {
    message: 'Phone number must be exactly 10 digits',
  })
  phoneNumber: string;
}
