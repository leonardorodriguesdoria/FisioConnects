/* eslint-disable prettier/prettier */
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Physiotherapist {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  phone: string;

  @Column()
  password: string;

  @Column({ unique: true })
  crefito: string;

  @Column()
  description: string;

  @Column({ default: 'https://ibb.co/27mgpNMx' })
  profilePicture: string;

  @Column('simple-array')
  specialties: string[];

  @Column({ nullable: true })
  resetToken: string;

  @Column({ nullable: true, type: 'timestamp' })
  resetTokenExpiresAt: Date;

  @Column({ default: 'unverified' })
  accountStatus: 'verified' | 'unverified';
}
