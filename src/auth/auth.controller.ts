import {
    BadRequestException,
    Body, ClassSerializerInterceptor,
    Controller,
    Get,
    NotFoundException,
    Post,
    Req,
    Res,
    UseInterceptors
} from '@nestjs/common';
import {UserService} from "../user/user.service";
import * as bcrypt from 'bcryptjs';
import {RegisterDto} from "./models/register.dto";
import {JwtService} from "@nestjs/jwt";
import {Request, Response} from 'express';

@UseInterceptors(ClassSerializerInterceptor)
@Controller()
export class AuthController {

    constructor(
        private userService: UserService,
        private jwtService: JwtService
        ) {
    }

    @Post('register')
    async register(@Body() body: RegisterDto) {
        if (body.password !== body.password_confirm) {
            throw new BadRequestException('Wachtwoord ongeldig is!');
        }
        const hashed = await bcrypt.hash(body.password, 12);

        return this.userService.create({
            first_name: body.first_name,
            last_name: body.last_name,
            email: body.email,
            password: hashed,
        });
    }

    @Post('login')
    async login(
        @Body('email') email: string,
        @Body('password') password: string,
        @Res() response: Response
    ) {
        const user = await this.userService.findOne({email});

        if (!user) {
            throw new NotFoundException('Gebruiker was niet gevonden');
        }

        if (!await bcrypt.compare(password, user.password)) {
            throw new BadRequestException('Ongeldige gegevens');
        }

        const jwt = await this.jwtService.signAsync({id: user.id});

        response.cookie('jwt', jwt, {httpOnly: true});
        return user;
    }


    @Get('user')
    async user(@Req() request: Request) {
        const cookie = request.cookies['jwt'];

        const data = await  this.jwtService.verifyAsync(cookie);

        return this.userService.findOne({id: data['id']});
    }

}
