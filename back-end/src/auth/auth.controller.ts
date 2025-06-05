import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  Put,
  ParseIntPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuthGuard } from 'src/guards/auth.guard';
import { CreatePhysiotherapistDto } from './dto/create-physiotherapist.dto';
import { LoginPhysiotherapistDto } from './dto/login-physiotherapist.dto';
import { UpdatePhysiotherapistDto } from './dto/update-physiotherapist.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('list')
  async listAllProfessionals() {
    return await this.authService.getAllProfessionals();
  }

  @Get(':id')
  async professionalProfile(@Param('id', ParseIntPipe) id: number) {
    return await this.authService.getProfessionalProfile(id);
  }

  @Post('register')
  async create(@Body() createPhysiotherapistDto: CreatePhysiotherapistDto) {
    await this.authService.registerProfessional(createPhysiotherapistDto);
    return {
      message:
        'Profissional cadastro com sucesso. Um código de verificação foi enviado para seu e-mail!',
    };
  }

  @Post('login')
  async login(@Body() loginPhysiotherapistDto: LoginPhysiotherapistDto) {
    return await this.authService.loginphysiotherapist(loginPhysiotherapistDto);
  }

  @UseGuards(AuthGuard)
  @Patch('update/:id')
  @UseInterceptors(FileInterceptor('image'))
  async updateProfile(
    @Body() updateProfileDto: UpdatePhysiotherapistDto,
    @UploadedFile() image: Express.Multer.File,
    @Param('id', ParseIntPipe) id: number,
  ) {
    if (image) {
      updateProfileDto.profilePicture = image.path;
    }

    const updateProfile = await this.authService.updatePhysiotherapistProfile(
      id,
      updateProfileDto,
    );

    return {
      message: 'Dados do perfil atualizados com sucesso!!!',
      updateProfile,
    };
  }

  @UseGuards(AuthGuard)
  @Delete(':id')
  async removeProfile(@Param('id', ParseIntPipe) id: number) {
    await this.authService.deleteProfile(id);
    return { message: 'Sua conta foi excluída com sucesso!!!' };
  }

  // @UseGuards(AuthGuard)
  // @Put('change-password')
  // async changePassword(@Body() changePasswordDto: ChangePasswordDto) {
  //   return this.authService.changePassword();
  // }

  @Post('forgot-password')
  async forgotPassword(@Body() body: ForgotPasswordDto) {
    await this.authService.forgotPassword(body.email);
    return {
      message: 'Se o e-mail existir, um link de recuperação será enviado.',
    };
  }

  @Post('reset-password')
  async resetPassword(@Body() body: ResetPasswordDto) {
    await this.authService.resetPassword(body.token, body.newPassword);
    return { message: 'Senha redefinida com sucesso.' };
  }
}
