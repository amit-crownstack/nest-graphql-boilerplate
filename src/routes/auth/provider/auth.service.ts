import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from 'src/routes/users/entity/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { LoginUserBodyDto } from '../dto/login-user-body.dto';
import { RegisterUserBodyDto } from '../dto/register-user-body.dto';
import { UsersService } from 'src/routes/users/provider/user.service';
import { ResponseMesages } from 'src/common/constants/response.messages';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private readonly userservice: UsersService,
  ) {}

  /**
   *
   * @param userDetail
   * @returns userDetail
   */
  async login(userDetail: LoginUserBodyDto): Promise<any> {
    // VALIDATE IF USER EXISTS
    const user = await this.userservice.getUserDetailByEmail(
      userDetail.userEmail,
    );
    if (!user) {
      throw new BadRequestException(ResponseMesages.EMAIL_NOT_FOUND);
    }
    // VALIDATE IF USER IS VERIFIED
    if (!user.isrestricted) {
      throw new BadRequestException(ResponseMesages.USER_RESTRICTED);
    }

    // VALIDATE IF PASSWORD IS CORRECT
    if (!(await bcrypt.compare(userDetail.userPassword, user.userpassword))) {
      throw new BadRequestException(ResponseMesages.WRONG_CREDENTIALS);
    }

    // VALIDATE IF USER IS ACTIVE
    if (!user.verified) {
      // TODO: Send OTP to user's email
      return user;
    } else {
      // VALIDATE IF DUAL AUTH IS ACTIVE
      if (user.dual_auth) {
        // TODO: Send OTP to user's email
        return user;
      } else {
        // ALLOW USER TO LOGIN WITH ACCESS TOKEN AND REFRESH TOKEN
        return user;
      }
    }
  }

  // Generate 6-digit OTP
  private generateOTP(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
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
    return user;
  }
}
