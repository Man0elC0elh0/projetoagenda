const mongoose = require('mongoose');
const validator = require('validator')
const bcrybtjs = require('bcryptjs')

const LoginSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
});

//BD trabalha com promises por isso deve-se utilizar async

const LoginModel = mongoose.model('Login', LoginSchema);

class Login {
  constructor(body) {
    this.body = body;
    this.errors = [];
    this.user = null;
  }

  async login() {
    this.valida();
    // checa se o array de errors está vazio
    if (this.errors.length > 0) return;
    this.user = await LoginModel.findOne({ email: this.body.email })

    if (!this.user) {
      this.errors.push('Usuário não existe');
      return;
    }
    if (!bcrybtjs.compareSync(this.body.password, this.user.password)) {
      this.errors.push('Senha inválida');
      this.user = null;
      return;
    }
  }

  // tudo que utilizar async precisa ter o await envolvido num bloco try catch
  async register() {
    this.valida();
    // checa se o array de errors está vazio
    if (this.errors.length > 0) return;

    await this.userExists();

    if (this.errors.length > 0) return;

    //hash
    const salt = bcrybtjs.genSaltSync();
    this.body.password = bcrybtjs.hashSync(this.body.password, salt);

    //envia para base de dados os dados limpos
    this.user = await LoginModel.create(this.body);
  }

  async userExists() {
    this.user = await LoginModel.findOne({ email: this.body.email })
    if (this.user) this.errors.push('Usuário já existe')
  }

  valida() {
    this.cleanUp();
    //validação
    //email valido
    if (!validator.isEmail(this.body.email)) this.errors.push('E-mail inválido');

    //a senha 3 a 50 caracteres
    if (this.body.password.length < 3 || this.body.password.length > 50) {
      this.errors.push('A senha precisa ter entre 3 e 50 caracteres.');
    }
  }
  //garantir que tudo dentro do body é uma string
  cleanUp() {
    for (const key in this.body) {
      if (typeof this.body[key] !== 'string') {
        this.body[key] = '';
      }
    }
    this.body = {
      email: this.body.email,
      password: this.body.password
    };
  }
}
module.exports = Login;