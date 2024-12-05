import {
  EntitySubscriberInterface,
  EventSubscriber,
  InsertEvent,
  UpdateEvent,
} from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { UserEntity } from '../user.entity';

@EventSubscriber()
export class UserSubscriber implements EntitySubscriberInterface<UserEntity> {
  // Indicates that this subscriber listens to the UserEntity
  listenTo() {
    return UserEntity;
  }

  // Before insert event, hash the password
  async beforeInsert(event: InsertEvent<UserEntity>) {
    if (event.entity.userpassword) {
      // Hash the password before inserting
      event.entity.userpassword = await bcrypt.hash(
        event.entity.userpassword,
        10,
      );
    }
  }

  // Before update event, hash the password if it's being updated
  async beforeUpdate(event: UpdateEvent<UserEntity>) {
    if (event.entity.userpassword) {
      // Hash the password before updating
      event.entity.userpassword = await bcrypt.hash(
        event.entity.userpassword,
        10,
      );
    }
  }
}
