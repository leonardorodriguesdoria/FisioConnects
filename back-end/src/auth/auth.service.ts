import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

//Repository Pattern
import { InjectRepository } from '@nestjs/typeorm';
import { QueryFailedError, Repository } from 'typeorm';

//Entitie
import { Physiotherapist } from 'src/entities/physiotherapist.entity';

//Services
import { JwtService } from '@nestjs/jwt';
//Interfaces
import { IPhysiotherapist } from 'src/shared/interfaces/physioterapist.interface';
import { IPhysiotherapistLogin } from 'src/shared/interfaces/physiotherapistLogin.interface';
import { IResetPhysiotherapistPassword } from 'src/shared/interfaces/physiotherapistResetPassword.interface';
import { IPhysiotherapistProfileUpdate } from 'src/shared/interfaces/physiotherapistProfileUpdate.interface';
//Utils
import { ObjectId } from 'mongodb';
import { comparePassword, hashPassword } from 'src/utils/hashPassword';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import { OTPService } from 'src/otp/otp.serivce';
import { OtpTypes } from 'src/otp/types/otpType';

@Injectable()
export class AuthService {
  private issuer = 'login';
  private audience = 'physiotherapist';
  constructor(
    @InjectRepository(Physiotherapist)
    private readonly physiotherapistRepository: Repository<Physiotherapist>,
    private readonly jwtService: JwtService,
    private readonly otpService: OTPService,
  ) {}

  createToken(user: Physiotherapist) {
    return {
      access_token: this.jwtService.sign(
        {
          name: user.name,
          email: user.email,
        },
        {
          expiresIn: '3 days',
          subject: String(user.id),
          issuer: this.issuer,
          audience: this.audience,
        },
      ),
    };
  }

  checkToken(token: string) {
    try {
      const data = this.jwtService.verify(token, {
        audience: this.audience,
        issuer: this.issuer,
      });
      return data;
    } catch (error) {
      throw new BadRequestException(
        'Ocorreu um erro na autenticação. Tente mais tarde',
      );
    }
  }

  //Cadastro Fisioterapeuta
  async registerProfessional(
    body: IPhysiotherapist,
  ): Promise<{ physiotherapist: Physiotherapist; otp: string }> {
    try {
      const {
        name,
        email,
        phone,
        description,
        password,
        crefito,
        specialties,
      } = body;

      const professionalAlreadyExists =
        await this.physiotherapistRepository.findOne({
          where: { email: email },
        });
      if (professionalAlreadyExists) {
        throw new ConflictException('Já existe um usuário com esse e-mail!!!');
      }

      const hashedPassword = await hashPassword(password);

      const newProfessional = this.physiotherapistRepository.create({
        name: name,
        email: email,
        phone: phone,
        description: description,
        password: hashedPassword,
        crefito: crefito,
        specialties: specialties,
      });

      await this.physiotherapistRepository.save(newProfessional);
      const otp = await this.otpService.generateOTP(
        newProfessional,
        OtpTypes.OTP,
      );
      return {
        physiotherapist: newProfessional,
        otp: otp,
      };
    } catch (error) {
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      if (error instanceof QueryFailedError) {
        throw new InternalServerErrorException(
          'Erro ao processar o banco de dados.',
        );
      }

      throw new InternalServerErrorException(
        'Erro interno no sistema. Por favor tente mais tarde.',
      );
    }
  }

  // Login Fisioterapeuta
  async loginphysiotherapist(body: IPhysiotherapistLogin) {
    try {
      const { email, password } = body;

      const physiotherapist = await this.physiotherapistRepository.findOne({
        where: { email: email },
      });

      if (!physiotherapist) {
        throw new NotFoundException('Usuário não econtrado!!!');
      }

      const isValidPassword = await comparePassword(
        password,
        physiotherapist.password,
      );

      if (!isValidPassword) {
        throw new UnauthorizedException('Email e/ou senha inválidos!!!');
      }

      return this.createToken(physiotherapist);
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new InternalServerErrorException(
        'Erro interno no sistema. Por favor, tente mais tarde!!!',
      );
    }
  }

  async forgotPassword(email: string) {
    const user = await this.physiotherapistRepository.findOne({
      where: {
        email: email,
      },
    });
    if (user) {
    }

    return { message: 'Se esse usuário existe, ele irá receber um e-mail' };
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.physiotherapistRepository.findOne({
      where: { resetToken: token },
    });
    if (!user || user.resetTokenExpiresAt < new Date()) {
      throw new BadRequestException('Token inválido ou expirado.');
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    user.resetToken = null;
    user.resetTokenExpiresAt = null;

    await this.physiotherapistRepository.save(user);
  }

  async reset(body: IResetPhysiotherapistPassword) {
    try {
      const id = 0;

      const result = await this.physiotherapistRepository
        .createQueryBuilder()
        .update(Physiotherapist)
        .set({ password: body.password })
        .where('id = :id', { id })
        .returning('*')
        .execute();

      const updatedUser = result.raw[0];

      if (!updatedUser) {
        throw new UnauthorizedException(
          'Usuário não encontrado ou não atualizado.',
        );
      }

      return this.createToken(updatedUser);
    } catch (error) {
      console.error('Erro ao resetar senha:', error);
      throw new InternalServerErrorException(
        'Erro interno do sistema. Por favor tente novamente mais tarde',
      );
    }
  }

  //--------------------------*--------------------//

  async getAllProfessionals() {
    try {
      const allProfessionals = await this.physiotherapistRepository.find({});

      const professionalsWithoutPassword = allProfessionals.map(
        ({ password, ...rest }) => rest,
      );

      return professionalsWithoutPassword;
    } catch (error) {
      throw new InternalServerErrorException(
        'Erro interno do sistema. Por favor tente novamente mais tarde',
      );
    }
  }

  async getProfessionalProfile(id: number) {
    try {
      const getProfessional = await this.physiotherapistRepository.findOne({
        where: {
          id: id,
        },
      });

      const { password, ...rest } = getProfessional;

      return rest;
    } catch (error) {
      throw new InternalServerErrorException(
        'Erro interno do sistema. Por favor tente novamente mais tarde',
      );
    }
  }

  async updatePhysiotherapistProfile(
    id: number,
    body: IPhysiotherapistProfileUpdate,
  ) {
    try {
      const { name, email, profilePicture, description, phone, specialties } =
        body;

      const physiotherapistExists =
        await this.physiotherapistRepository.findOne({
          where: {
            id: id,
          },
        });
      if (!physiotherapistExists) {
        throw new NotFoundException(
          'Profissional não encontrado. Ocorreu um erro, tente mais tarde',
        );
      }

      if (body.email && body.email !== physiotherapistExists.email) {
        const emailInUse = await this.physiotherapistRepository.findOne({
          where: { email: body.email },
        });
        if (emailInUse) {
          throw new ConflictException(
            'Este email já está em uso por outro profissional.',
          );
        }
      }

      const updatedData = {
        ...physiotherapistExists,
        ...body,
      };

      await this.physiotherapistRepository.update(id, updatedData);

      return await this.physiotherapistRepository.findOne({
        where: { id: id },
      });
    } catch (error) {
      throw new InternalServerErrorException(
        'Erro interno do sistema. Por favor tente mais tarde',
      );
    }
  }

  async deleteProfile(id: number) {
    try {
      const physioterapistProfile = this.physiotherapistRepository.findOne({
        where: {
          id: id,
        },
      });

      if (!physioterapistProfile) {
        throw new NotFoundException(
          'Ocorreu um erro, perfil não econtrado!!!. Tente mais tarde',
        );
      }

      await this.physiotherapistRepository.delete(id);

      return true;
    } catch (error) {
      throw new InternalServerErrorException(
        'Erro interno do sistema. Por favor tente mais tarde',
      );
    }
  }
}
