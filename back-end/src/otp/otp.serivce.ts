/* eslint-disable prettier/prettier */
import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { OTP } from '../entities/otp.entity';
import { MoreThan, Repository } from 'typeorm';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { hashOTP } from 'src/utils/hashPassword';
import { OtpTypes } from './types/otpType';
import { Physiotherapist } from 'src/entities/physiotherapist.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OTPService {
  constructor(
    @InjectRepository(OTP)
    private otpRepository: Repository<OTP>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async generateOTP(
    physiotherapist: Physiotherapist,
    type: OtpTypes,
  ): Promise<string> {
    if (type === OtpTypes.OTP) {
      const otp = crypto.randomInt(10000, 99999).toString();
      const hashedOTP = await hashOTP(otp);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

      const existingOTP = await this.otpRepository.findOne({
        where: { physiotherapist: { id: physiotherapist.id }, type },
      });

      if (existingOTP) {
        //update exisiting token
        existingOTP.token = hashedOTP;
        existingOTP.expiresAt = expiresAt;
        await this.otpRepository.save(existingOTP);
      } else {
        //create otp entity
        const otpEntity = this.otpRepository.create({
          physiotherapist,
          token: hashedOTP,
          type,
          expiresAt,
        });

        await this.otpRepository.save(otpEntity);
      }
      return otp;
    } else if (type === OtpTypes.RESET_LINK) {
      const resetToken = this.jwtService.sign(
        { id: physiotherapist.id, email: physiotherapist.email },
        {
          secret: this.configService.get<string>('JWT_RESET_SECRET'),
          expiresIn: '15m',
        },
      );

      return resetToken;
    }
  }

  async validateOTP(userId: number, token: string): Promise<boolean> {
    const validToken = await this.otpRepository.findOne({
      where: {
        physiotherapist: { id: userId },
        expiresAt: MoreThan(new Date()),
      },
    });

    if (!validToken) {
      throw new BadRequestException(
        'Código de validação expirou, solicite um novo.',
      );
    }

    const isMatch = await bcrypt.compare(token, validToken.token);

    if (!isMatch) {
      throw new BadRequestException('Código inválido. Tente denovo');
    }

    return true;
  }

  async validateResetPassword(token: string) {
    try {
      //verify the JWT token and decode it
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_RESET_SECRET'),
      });

      //return the user id extracted from token if verification succeeds
      return decoded.id;
    } catch (error) {
      //handle expired token
      if (error?.name === 'TokenExpiredError') {
        throw new BadRequestException(
          'The reset token has expired.Please request a new one',
        );
      }
      throw new BadRequestException('Invalid or malformed reset token');
    }
  }
}
