import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../entity/user.entity';
import { Repository } from 'typeorm';

/**
 * User Service
 */

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
  ) {}

  async getUserDetailByEmail(userEmail: string) {
    const userDetail = this.userRepository.findOne({
      where: {
        useremail: userEmail,
      },
    });
    return userDetail;
  }
}
