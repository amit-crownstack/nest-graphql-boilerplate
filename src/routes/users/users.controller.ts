import { Controller } from '@nestjs/common';
import { UsersService } from './provider/user.service';
import { ApiTags } from '@nestjs/swagger';

@Controller('users')
@ApiTags('Users')
export class UsersController {
  constructor(private userService: UsersService) {}
}
