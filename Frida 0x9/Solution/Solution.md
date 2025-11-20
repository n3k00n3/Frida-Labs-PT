
## Pré-requisitos

* Básico de Engenharia Reversa usando JADX.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.
* Conhecimentos básicos de assembly x86/ARM64 e reversing.

## Desafio 0x9

Vamos começar instalando o aplicativo.

![](images/1.png)

Temos apenas um botão. Vamos clicar nele.

![](images/2.png)

Nenhuma pista interessante. Vamos verificar no JADX.

![](images/3.png)

Logo no início encontramos a declaração da função nativa.
O método `check_flag` está definido na biblioteca `a0x9`. Esta função:

* não recebe argumentos
* retorna um inteiro

Quando o botão é clicado, o retorno de `check_flag()` é comparado com `1337`.
Se for igual, a flag é descriptografada e exibida. Caso contrário, é mostrado “Try again”.

Portanto, para obter a flag basta **alterar o retorno** da função para `1337`.

Vamos analisar a biblioteca `a0x9`.

![](images/4.png)

Carregando a biblioteca no Ghidra:

![](images/5.png)
![](images/6.png)

A função não faz praticamente nada. Apenas retorna `1`.

Portanto, podemos simplesmente hookar essa função e alterar o valor retornado para `1337`.

Observe também o nome real da função no espaço nativo:

```
Java_com_ad2001_a0x9_MainActivity_check_1flag
```

---

## Hook com Frida

Modelo básico:

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {},
    onLeave: function (retval) {}
});
```

Primeiro, vamos obter o endereço da função com `Module.enumerateExports()`:

![](images/7.png)

Script:

```javascript
var check_flag = Module.enumerateExports("liba0x9.so")[0]['address']
Interceptor.attach(check_flag, {
    onEnter: function () {

    },
    onLeave: function (retval) {

    }
});
```

Agora, vamos modificar o valor retornado no `onLeave()`:

```javascript
var check_flag = Module.enumerateExports("liba0x9.so")[0]['address']
Interceptor.attach(check_flag, {
    onEnter: function () {

    },
    onLeave: function (retval) {
        console.log("Original return value: " + retval);
        retval.replace(1337);
    }
});
```

Executando o script:

![](images/8.png)

Clicando no botão:

![](images/9.png)
![](images/10.png)

Flag obtida com sucesso.
