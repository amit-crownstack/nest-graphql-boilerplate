import { Entity, Column, ManyToOne, JoinColumn } from 'typeorm';

import { UserRole } from './types/userRole';
import { UserRegistrationType } from './types/userRegistrationType';
import { AccountType } from './types/accType';
import { CounselorEntity } from 'src/routes/counselor/entity/counselor.entity';
import { BaseEntity } from 'src/common/entity/baseEntity';

@Entity('users')
export class UserEntity extends BaseEntity {
  @Column({ type: 'varchar', length: 255, nullable: true })
  username: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  useremail: string;

  @Column({ type: 'varchar', length: 255 })
  userpassword: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  profilepicture: string;

  @Column({ type: 'boolean', default: false })
  verified: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true })
  phonenumber: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  countrycode: string;

  @Column({ type: 'boolean', default: false })
  isrestricted: boolean;

  // Current counselor relation (Many-to-One: A user has one counselor)
  // relationship is made nullable, so it can be empty for new users.
  @ManyToOne(() => CounselorEntity, { nullable: true })
  @JoinColumn({ name: 'counselor_id' })
  current_counselor: CounselorEntity;

  // Counselor history (JSON array, stored as a stringified JSON in DB)
  @Column({ type: 'json', default: [] })
  counselor_history: CounselorEntity[];

  // User role - Enum
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.PATIENT,
  })
  user_role: UserRole;

  // Account type - Enum
  @Column({
    type: 'enum',
    enum: AccountType,
    default: AccountType.INDIVIDUAL,
  })
  acc_type: AccountType;

  // Registration reference - Enum
  @Column({
    type: 'enum',
    enum: UserRegistrationType,
    default: UserRegistrationType.DIRECT,
  })
  reg_ref: UserRegistrationType;

  // Partner reference - Self-join (User to User relation)
  @ManyToOne(() => UserEntity, { nullable: true })
  @JoinColumn({ name: 'partner_ref' })
  partner_ref: UserEntity;

  // Last login IP
  @Column({ type: 'varchar', length: 255, nullable: true })
  last_login_ip: string;

  // Dual authentication enabled
  @Column({ type: 'boolean', default: false })
  dual_auth: boolean;

  // Trusted IP history
  @Column({
    type: 'json',
    default: [],
  })
  ipHistory: { isTrusted: boolean; IP: string }[];
}
