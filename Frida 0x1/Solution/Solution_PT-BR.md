
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender códigos Java.
* Capacidade de escrever pequenos trechos de código em JavaScript.
* Familiaridade com adb.
* Dispositivo Rootado.

## Frida

Vamos iniciar com a primeira coisa. O que é Frida?

[Frida](https://frida.re/) é como uma ferramenta mágica para seu computador ou dispositivo móvel. Ele te ajuda a visualizar o que está acontecendo dentro de outros programas e aplicativos, mesmo que você não tenha o código original. É como olhar através de uma janela para entender como as coisas funcionam. Frida também pode hookar as funcionalidades dos programas. Com Frida você tem o poder de modificar e observar como um programa ou aplicativo móvel funciona por dentro.

* **Intercpetando Chamadas de Funções:** Frida permite que você identifique funções especificas ou métodos dentro de um programa ou aplicativo e interceptar elas. Quando essas funções são chamadas, Frida pode realizar mudanças nos dados que as funções recebem ou verificar o que elas estão fazendo.

* **Observando e Modificando:** Você pode monitorar o que está acontecendo dentro do programa em tempo de execução. Por exemplo, você pode ver os valotes das variáveis, entender o fluxo do programa e modificar o dado ou código que está sendo executado.

* **Debugging e Engenharia Reversa**: Essa capacidade é valiosa para o debugging, engenharia reversa e análise de segurança. É utilizada por desenvolvedores para diagnosticar e corrigir bugs em seus programas, assim como também é utilizada por profissionais de segurança, para descobrir vulnerabilidades e potenciais ameaças.

* **Análise Dinamica:** Diferente de ferramentas tradicionais de debug, Frida não requer acesso ao código fonte original. Podendo trabalhar com código compilado, Tornando útil para para examinar aplicações com código fechado.

Nós vamos cobrir alguns dos usos fundamentais do Frida para a análise de aplicações Android.

## Setup

Para configurar Frida, precisamos instalar `frida-tools` em nosso sistema e executar o `frida-server` no dispostivo. Você pode instalar usando `pip`.

```bash
pip install frida-tools
```

Próxima parte é copiar o servidor frida no dispostivo.

```
https://github.com/frida/frida/releases
```

Você  deve selecionar o servidor baseado na sua arquitetura. Se eu estiver usando um emulador no Android Studio ou Genymotion, em uma plataforma x86, teremos que fazer o download da versão x86 do frida-server.

![](images/1.png)

Se você não sabe qual a arquitetura de seu dispositivo, use o comando a seguir.

```bash
adb shell getprop ro.product.cpu.abi
```

![](images/2.png)

Se o seu dispositivo é arm64, baixe o servidor arm64.

![](images/3.png)

Depois de baixar o binário, extraia e envie para uma pasta com permissão de escrita como por exemplo a pasta `/data/local/tmp`.

![](images/4.png)

```bash
adb push frida-server-16.1.4-android-x86 /data/local/tmp
```

![](images/5.png)

Agora navegue até a pasta `tmp`. Para obter uma shell dentro do dispositivo utilize o comando `adb shell`.

```bash
D:\Downlaods> adb shell
generic_x86:/ # cd /data/local/tmp/
generic_x86:/data/local/tmp # ls
frida-server-16.0.19-android-x86  frida-server-16.1.4-android-x86  lldb-server  perfd  start_lldb_server.sh
generic_x86:/data/local/tmp #
```

Vamos garantir a permissão de execução para o binário `frida-server`.

```bash
generic_x86:/data/local/tmp # chmod +x frida-server-16.1.4-android-x86
```

Finalmente podemos executar o binário do servidor.

![](images/6.png)

Isso é tudo que precisamos fazer para executar o `frida-server`. Se você encontrar algum erro durante a execução, Recomendo pesquisar pelo erro no buscador google ou outro de sua preferência. Você também pode checar o repositório git por problemas conhecidos e potenciais soluções.

## Uso básico do Frida

Se você deseja verificar a lista de pacotes instalados em seu dispositivo, você pode utilizar o seguinte comando:

```bash
frida-ps -Uai
```

* `frida-ps`: Exibe quais processos estão sendo executados no dispositivo Android.
* `-U`: Essa opção é utilizada para listar os processos em dispositivos conectados via USB (fisícos ou emulados).
* `-a`: Essa opção é utilizada para listar todos os processos.
* `-i`: Essa opção é utilizada para incluir detalhes sobre cada processo, como ID do processo (PID) e o nome dos processos.

![](images/7.png)

Se você deseja verificar o pacote de uma aplicação especifica, você pode utilizar o comando `grep`.

```bash
frida-ps -Uai | grep '<nome_da_aplicação>'
```

Para anexar frida com uma aplicação é necessário o nome do pacote. Depois de verificar o nome do pacote é possível anexar utilizando o seguinte comando:

```bash
frida -U -f <package_name>
```

Vamos ver um exemplo.

Iremos tentar anexar frida com a aplicação de calculadora. O nome do pacote é `com.ad2001.calculator`.

```bash
frida -U -f com.ad2001.calculator
```

![](images/8.png)

Verificando o emulador.

![](images/9.png)

Frida carregou a aplicação em nosso dispositivo. Agora que a aplicação está spawned, e anexamos frida, podemos proceder com nossa instrumentação dinâmica.

## Introdução ao Hooking

Vamos iniciar com a parte mais básica.

O que é hooking ?

**Hooking** se refere ao processo de interceptação e modificação do comportamento de funções ou métodos em uma aplicação ou do próprio sistema Android. Por exemplo, podemos 'hookar' um método em nossa aplicação e modificar sua funcionalidade, inserido nosso próprio código.

Agora, Vamos tentar 'hookar' um metódo em uma aplicação. Vamos fazer isso utilizando a API JavaScript, mas tenha em mente que Frida também tem suporte para Python.

## Desafio 0x1

A aplicação que utilizaremos é um APK de desafio. O desafio está essencialmente no estilo CTF, e o nome do APK é `frida 0x1`. Vamos encontrar o nome do pacote.

![](images/10.png)

Antes de anexar a aplicação ao Frida, vamos tirar um momento para entender a aplicação. Assim que abrimos a aplicação, podemos ver a interface como da seguinte imagem:

![](images/11.png)

A aplicação exige que seja inserido uma número. Vamos enviar um número e verificar o que acontece.

![](images/12.png)

A aplicação diz `Try again`. Então, vamos tentar decompilar a aplicação utilizando Jadx.

![](images/13.png)

Apenas passando rapidamente o olho pelo código Java, conseguimos entender que a aplicação recebe o texto inserido pelo usuário, converte esse texto para um inteiro e passa esse inteiro para um método chamado `check`.

```java
public void onClick(View view) {
    String obj = editText.getText().toString();
    if (TextUtils.isDigitsOnly(obj)) {
        MainActivity.this.check(i, Integer.parseInt(obj));
    } else {
        Toast.makeText(MainActivity.this.getApplicationContext(), "Enter a valid number !!", 1).show();
    }
}
```

Junto com o número digitado pelo usuário, outro valor inteiro também é passado.

![](images/14.png)

Um valor aleatório é gerado pela função `get_random()` quando a aplicação inicia. Esse valor fica dentro do intervalo de 0 a 100 e é armazenado na variável `i`. A função `get_random()` é chamada quando a aplicação inicia, mas apenas uma vez. Portanto, o número aleatório não mudará enquanto o app estiver aberto. A cada nova execução da aplicação, um novo número aleatório será gerado.

Agora vamos ver o que está acontecendo na função `check()`.

```java
void check(int i, int i2)
```

Aqui `i` se refere ao número aleatório passado e `i2` ao número inteiro convertido a partir da entrada do usuário.

```java
if ((i * 2) + 4 == i2)
```

A declaração `if` verifica se o número de entrada é igual ao (valor aleatório * 2 + 4). Se houver uma correspondência, ele decodifica a FLAG hardcoded e a exibe no `textview`. Para obter a flag, precisamos descobrir o número aleatório e realizar as operações aritméticas especificadas, depois inserir o resultado na aplicação.

Sim, você pode resolver isso facilmente usando outros métodos, mas o objetivo principal aqui é se familiarizar com o Frida. Para isso, precisamos de uma forma de obter o número aleatório usando Frida, e existem algumas maneiras de fazer isso:

* Hookando a função `get_random()`.

  * Como sabemos que o número aleatório é gerado dentro do método `get_random()`, podemos hookar esse método para obter o valor de retorno, ou podemos sobrescrever o valor de retorno com um valor arbitrário, de modo que `get_random()` retorne o valor que fornecemos para a função `check()`.

* Hookando a função `check()`.

  * Os argumentos passados para o método `check()` contêm o número aleatório. Assim, podemos tentar hookar esse método para capturar os argumentos e descobrir o número aleatório.

Agora que já sabemos como resolver isso, vamos tentar escrever alguns scripts Frida.

## Hooking a method

Primeiro, deixe-me te mostrar um modelo, então explicarei.

```javascript
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<args>) {

    /*
      NOSSA PRÓPRIA IMPLEMENTAÇÃO DO MÉTODO
    */

  }

})
```

* `Java.perform` é uma função do Frida usada para criar um contexto especial para o seu script interagir com o código Java em aplicações Android. É como abrir uma porta para acessar e manipular o código Java em execução dentro do app. Uma vez dentro desse contexto, você pode realizar ações como hookar métodos ou acessar classes Java para controlar ou observar o comportamento da aplicação.

* `var <class_reference> = Java.use("<package_name>.<class>");`

  Aqui, você declara uma variável `<class_reference>` para representar uma classe Java dentro da aplicação Android alvo. Você especifica a classe a ser usada com a função `Java.use`, que recebe o nome da classe como argumento. `<package_name>` representa o nome do pacote da aplicação Android, e `<class>` representa a classe com a qual você deseja interagir.

* `<class_reference>.<method_to_hook>.implementation = function(<args>) {}`

  Dentro da classe selecionada, você especifica o método que deseja hookar acessando-o usando a notação `<class_reference>.<method_to_hook>`. É aqui que você pode definir sua própria lógica a ser executada quando o método hookado for chamado. `<args>` representa os argumentos passados para a função.

Agora, a próxima pergunta é: o que vamos hookar?

## Hooking the get_random() method

Vamos tentar hookar o método `get_random()` desta vez. Vamos escrever nosso script Frida para isso.

Primeiro precisamos do nome do pacote – nós já sabemos:

```text
com.ad2001.frida0x1
```

Em seguida, precisamos identificar o nome da classe onde está localizado o método que queremos hookar.

![](images/15.png)

Como podemos ver, devemos obter a referência para `MainActivity`.

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");

})
```

Depois, vamos modificar o script para incluir nossa implementação personalizada do método. O método a ser hookado é `get_random`.

```java
int get_random() {
    return new Random().nextInt(100);
}
```

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){

    console.log("This method is hooked");

  }

})
```

Quando executamos esse script, ele hooka a função `get_random()`. Isso significa que, sempre que a função `get_random()` for chamada, o nosso código personalizado será executado no lugar do original. Nesse caso, quando o método for acionado, ele imprimirá `This method is hooked`. O script ainda não está completo, e note que não estou passando nenhum argumento na `function()` porque `get_random()` não recebe parâmetros.

Agora vamos executar o script para observar o comportamento.

Primeiro, vamos anexar a aplicação com o Frida:

```bash
frida -U -f com.ad2001.frida0x1
```

![](images/16.png)

Beleza, agora o Frida foi anexado. Para rodar o script, simplesmente copie e cole o código no console e aperte Enter.

![](images/17.png)

Se o script não tiver erros, ele deve aparecer como mostrado acima. Se ocorrer algum erro, o Frida irá avisar, e você deverá revisar o script.

Vamos tentar inserir um número.

![](images/19.png)

A aplicação exibe a mensagem `Try again`. Obviamente, não sabemos o número. No entanto, quando verificamos o console do Frida, não vemos nenhuma informação ou saída.

![](images/20.png)

A razão disso é que a função `get_random()` é executada quando o app é iniciado. Estamos injetando o script depois que `get_random()` já foi executada. Se você olhar a descompilação, consegue entender isso.

Então, o que vamos fazer?

Precisamos injetar o script ao mesmo tempo em que a aplicação é carregada, permitindo que a gente hooke esse método antes de sua execução. Para isso, podemos usar a opção `-l`. Primeiro, vamos salvar o script em um arquivo.

Eu salvei meu script como `script.js`. Agora vamos carregar esse script usando a opção `-l`.

```bash
frida -U -f com.ad2001.frida0x1 -l .\script.js
```

![](images/21.png)

Nós conseguimos hookar o método `get_random()`, mas estamos recebendo um erro. Ele diz que `get_random()` esperava um valor de retorno. Se olharmos a implementação de `get_random()`, veremos que ela retorna um número.

```java
int get_random() {
    return new Random().nextInt(100);
}
```

No nosso script, substituímos a implementação original do método `get_random()` pela nossa, mas não fornecemos um valor de retorno. Esse valor de retorno é atribuído à variável `i` e é usado na função `check()`. Então, vamos tentar fornecer um valor de retorno. Você pode usar qualquer valor.

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){

    console.log("This method is hooked");
    console.log("Returning 5")

    return 5;

  }

})
```

Eu usei o valor 5. Agora, se injetarmos esse código, a função `get_random()` retornará `5` sempre.

Vamos rodar o script:

```bash
frida -U -f com.ad2001.frida0x1 -l .\script.js
```

![](images/22.png)

Podemos ver que nenhum erro foi disparado; o método foi chamado e retornou o valor `5`.

Agora, `5` será passado para a função `check()`. Vamos calcular o valor para satisfazer o `if` e obter a flag:

```java
if ((i * 2) + 4 == i2)
```

Então, 5 * 2 + 4 é igual a 14. Se digitarmos 14 como entrada, podemos obter a flag. Vamos tentar.

![](images/23.png)

Perfeito! Conseguimos a flag.

Agora vamos tentar recuperar o valor aleatório originalmente gerado. Para isso, precisamos obter o valor retornado pela função original `get_random()`. Vamos ver como fazer isso.

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){

    console.log("This method is hooked");
    var ret_val = this.get_random();
    console.log("The return value is " + ret_val);

  }

})
```

O que fizemos aqui foi hookar o método `get_random()`. Dentro desse hook, chamamos o `get_random()` original usando `this.get_random()`. A palavra-chave `this` se refere ao objeto atual. Como esse método retorna o valor original, armazenamos o resultado na variável `ret_val`. Mas, se executarmos esse script assim, a aplicação irá travar, pois `get_random()` precisa fornecer um valor de retorno. Então podemos retornar o valor original, e para burlar a verificação podemos usar o valor aleatório original armazenado em `ret_val`.

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){

    console.log("This method is hooked");
    var ret_val = this.get_random();
    console.log("The return value is " + ret_val);
    console.log("The value to bypass the check " + (ret_val * 2 + 4 )) // To bypass the check
    return ret_val; // returning the original random value from the get_random method

  }

})
```

Vamos salvar e rodar esse script.

```bash
frida -U -f com.ad2001.frida0x1 -l .\bypass.js
```

![](images/24.png)

O valor aleatório gerado é `35`. Nosso script também calcula o valor para burlar a verificação. Então vamos tentar inserir o valor `74`.

![](images/25.png)

Maravilha, conseguimos a flag.

## Hooking the check() method

Vamos testar o segundo método que mencionei no início. Vamos hookar o método `check()` e capturar seus argumentos, porque os argumentos passados para `check()` contêm o número aleatório.

```java
...
    final int i = get_random();
...

void check(int i, int i2) {
    if ((i * 2) + 4 == i2) {

        ...
        ...
        ...

    }
}
```

Se analisarmos os argumentos da função `check`, o primeiro argumento, `i`, representa o número aleatório, e o segundo, `i2`, corresponde ao número inserido pelo usuário. Vamos capturar e exibir ambos os argumentos usando Frida.

Quando lidamos com hook de métodos que possuem argumentos, é importante especificar os tipos esperados usando a palavra-chave `overload(arg_type)`. Além disso, certifique-se de incluir esses argumentos especificados na sua implementação ao hookar o método. Aqui, nossa função `check()` recebe dois inteiros, então podemos especificar assim:

```javascript
a.check.overload('int', 'int').implementation = function(a, b) {

  ...

}
```

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.check.overload('int', 'int').implementation = function(a, b) { // The function takes two arguments - check(random, input)
    console.log("The random number is " + a);
    console.log("The user input is " + b);
  }

})
```

Depois de obter esses argumentos, o objetivo principal é garantir que a função `check` continue funcionando normalmente, já que ela contém o código para gerar a flag. O foco aqui é extrair o valor aleatório sem interromper a funcionalidade da função. Então, podemos simplesmente chamar a função `check()` original, assim como fizemos acima com `get_random`. Não se esqueça de passar os argumentos para a chamada original de `check()`.

```javascript
Java.perform(function() {
  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.check.overload('int', 'int').implementation = function(a, b) {
    // The function takes two arguments; check(random, input)
    console.log("The random number is " + a);
    console.log("The user input is " + b);
    this.check(a, b); // Call the check() function with the correct arguments
  }
});
```

Vamos tentar rodar esse script. Não precisamos carregar esse script no início, já que a função `check()` só é chamada quando clicamos no botão.

```bash
frida -U -f com.ad2001.frida0x1
```

![](images/26.png)

Vamos inserir um valor e clicar no botão de submit.

![](images/27.png)

Vemos que o número aleatório gerado é 16. Então, digitando (16 * 2 + 4), ou seja, `36`, conseguimos a flag.

Antes de concluir esse exemplo, quero mostrar mais uma maneira de obter a flag.

Sabemos que, para obter a flag, nossa entrada precisa ser igual ao resultado de (número aleatório * 2 + 4). Então, por que simplesmente não chamar a função `check()` com dois números que satisfaçam essa condição? Dessa forma, não precisamos nos preocupar com o número aleatório, já que estamos fornecendo nossa própria entrada para a função `check()`.

Vamos tentar. Vou fornecer o número `4` como nossa entrada e (4 * 2 + 4) como o segundo argumento, o que é igual a `12`.

```javascript
Java.perform(function() {
  var a = Java.use("com.ad2001.frida0x1.MainActivity");
  a.check.overload('int', 'int').implementation = function(a, b) {
    this.check(4, 12);
  }
});
```

![](images/28.png)

![](images/29.png)

Como esperado, conseguimos a flag.

Esses são os fundamentos de hookar um método com o Frida e exibir seus argumentos e valores de retorno. Frida é uma ferramenta muito poderosa, e exploraremos alguns de seus recursos principais ao longo da série.