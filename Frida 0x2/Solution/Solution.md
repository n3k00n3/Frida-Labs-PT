
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de ler e entender código Java.
* Capacidade de escrever pequenos trechos de código em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x2

Vamos começar com nosso APK. Então, vamos instalar a aplicação e dar uma olhada.

![](images/1.png)

A aplicação é bem simples, consiste apenas em um **TextView**, sem botões ou qualquer outro elemento. O texto exibido no TextView diz **"HOOK ME!"**.
Bom… é exatamente isso que vamos fazer.

Vamos usar o **jadx** para engenharia reversa da aplicação.

![](images/2.png)

Como podemos ver, é uma aplicação bem pequena.
A única coisa que ela faz é configurar o TextView.
Está evidente que a flag está dentro do método `get_flag()`.

Porém, o método **não é chamado** de lugar nenhum na aplicação.

O método `get_flag()` é responsável por:

* Descriptografar a flag
* Exibir no TextView

Ao analisar rapidamente, percebemos que **AES** está sendo utilizado.
Apesar de existirem outros métodos para descobrir a flag facilmente, o objetivo aqui é usar Frida.

Outra informação importante: existe uma condição `if` que verifica se o argumento `a` é igual a **4919**.

Ou seja: para obter a flag, só precisamos **chamar o método `get_flag()` passando 4919**.

Podemos fazer isso facilmente com Frida.

---

Vamos iniciar encontrando o nome do pacote da aplicação:

![](images/3.png)

O nome do pacote é:

```
com.ad2001.frida0x2
```

Também podemos confirmá-lo no jadx:

![](images/4.png)

---

Vamos começar a escrever nosso script Frida.

Template para chamar método **estático**:

```javascript
Java.perform(function() {

    var <class_reference> = Java.use("<package_name>.<class>");
    <class_reference>.<static_method>();

})
```

Aplicando ao nosso caso:

```javascript
Java.perform(function() {

    var a = Java.use("com.ad2001.frida0x2.MainActivity");

})
```

Obtivemos a referência para `MainActivity`.
Agora vamos chamar `get_flag()` passando **4919**, para satisfazer o `if`.

```javascript
Java.perform(function() {

    var a = Java.use("com.ad2001.frida0x2.MainActivity");
    a.get_flag(4919);

})
```

---

Agora vamos executar:

```
frida -U -f com.ad2001.frida0x2
```

![](images/5.png)

Pressione **ENTER** para rodar o script.

Agora verifique o dispositivo:

![](images/6.png)

---

BOOM! FLAG obtida!

Essa é a forma de chamar **métodos estáticos** utilizando Frida.