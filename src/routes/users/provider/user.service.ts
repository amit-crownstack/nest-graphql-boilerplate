import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../entity/user.entity';
import { Repository } from 'typeorm';
import { UserSession } from 'src/routes/auth/entity/session.entity';

/**
 * User Service
 */

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    @InjectRepository(UserSession)
    private userSession: Repository<UserSession>,
  ) {}

  async getUserDetailByEmail(userEmail: string) {
    const userDetail = this.userRepository.findOne({
      where: {
        useremail: userEmail,
      },
    });
    return userDetail;
  }

  async updateRefreshToken(userID: string, refreshToken: string) {
    const checkIfSessionExist = await this.userSession.findOne({
      where: {
        userId: userID,
      },
    });
    if (checkIfSessionExist) {
      return this.userSession.update(
        { userId: userID },
        { refreshToken: refreshToken },
      );
    } else {
      return this.userSession.save({
        userId: userID,
        refreshToken: refreshToken,
      });
    }
  }

  async findSessionById(userID: string) {
    return this.userSession.findOne({
      where: {
        userId: userID,
      },
    });
  }

  async findUserById(userID: string) {
    return this.userRepository.findOne({
      where: {
        id: userID,
      },
    });
  }
}
