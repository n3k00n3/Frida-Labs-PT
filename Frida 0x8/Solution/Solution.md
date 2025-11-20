
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.
* Conhecimentos básicos de Assembly x86/ARM64 e reversing.

## Desafio 0x8

Este APK é diferente dos anteriores
Agora estamos lidando com **bibliotecas nativas** (JNI + NDK).

O **Android NDK** permite incluir código nativo escrito em **C/C++**, empacotado em arquivos `.so` (shared object).
Frida também permite hookar esses trechos de código dentro das libs nativas.

Primeiro, abrimos o app:

![](images/1.png)

Temos um campo de texto — vamos testar:

![](images/2.png)

Nada acontece. Vamos abrir no jadx:

![](images/3.png)

Logo no início vemos a declaração da função nativa `cmpstr`:

```java
public native int cmpstr(String str);

static {
    System.loadLibrary("frida0x8");
}
```

A função recebe uma *string* e retorna um `int`.
Também vemos que a biblioteca **`frida0x8`** é carregada em tempo de execução.

Agora na callback do botão:

```java
String ip = MainActivity.this.edt.getText().toString();
int res = MainActivity.this.cmpstr(ip);
if (res == 1) {
    Toast.makeText(MainActivity.this, "YEY YOU GOT THE FLAG " + ip, 1).show();
} else {
    Toast.makeText(MainActivity.this, "TRY AGAIN", 1).show();
}
```

**A entrada do usuário é o próprio valor correto da flag!**
Se o retorno for `1` → FLAG exibida 

---

## Analisando a biblioteca nativa

Biblioteca encontrada em:

![](images/4.png)

Eu usarei a versão **x86** no emulador do Android Studio:

![](images/5.png)

Extraindo com **apktool**:

![](images/6.png)

Vamos analisar `libfrida0x8.so` com **Ghidra**:

![](images/7.png)
![](images/8.png)
![](images/9.png)

Abra a lista de funções:

![](images/10.png)

A função `cmpstr` aparece como:

```
Java_com_ad2001_frida0x8_MainActivity_cmpstr
```

Isso é apenas convenção de nomes JNI.

Decompilação:

![](images/11.png)

Aqui está o código fonte equivalente para facilitar:

```c
const char *hardcoded = "GSJEB|OBUJWF`MBOE~";
for (int i = 0; i < strlen(hardcoded) ; i++) {
    password[i] = (char)(hardcoded[i] - 1);
}
int result = strcmp(inputStr, password);
return (result == 0) ? 1 : 0;
```

O que acontece?

* A string `"GSJEB|OBUJWF\`MBOE~"`é **desofuscada** com`-1` no ASCII
* O resultado é comparado com nossa entrada usando `strcmp`
* Se forem iguais → retorno `1` → FLAG mostrada

Logo:

> **A flag = valor da string após esse -1**

Mas claro… vamos fazer isso **com Frida** 

---

## Hookando funções nativas com Frida

Usaremos **`Interceptor`**:

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {},
    onLeave: function (retval) {}
});
```

Agora precisamos do endereço da função nativa `strcmp`.

Podemos obtê-lo com:

```javascript
Module.findExportByName("libc.so", "strcmp")
```

---

### Script inicial

```javascript
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");
Interceptor.attach(strcmp_adr, {
    onEnter: function (args) {
        console.log("Hooking strcmp");
    }
});
```

Rodando e clicando no botão:

![](images/23.png)
![](images/24.png)

Problema: O log aparece **milhões de vezes** 
Porque hookamos **todas** as chamadas de `strcmp`.

---

## Filtro: apenas quando a input da UI estiver envolvida

Vamos ler os argumentos da função:

`strcmp(a, b) → args[0], args[1]`

```javascript
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");
Interceptor.attach(strcmp_adr, {
    onEnter: function (args) {
        var arg0 = Memory.readUtf8String(args[0]);
        if (arg0.includes("Hello")) {
            console.log("Hooking strcmp");
        }
    }
});
```

Testando com input "Hello":

![](images/25.png)
![](images/26.png)

Agora apenas **1** log → ótimo

---

## Extraindo a FLAG!

Agora vamos ler o **segundo argumento** (string secreta):

```javascript
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");
Interceptor.attach(strcmp_adr, {
    onEnter: function (args) {
        var arg0 = Memory.readUtf8String(args[0]); // input
        var flag = Memory.readUtf8String(args[1]); // string da lib

        if (arg0.includes("Hello")) {
            console.log("Input: " + arg0);
            console.log("The flag is: " + flag);
        }
    }
});
```

Resultado:

![](images/27.png)

⚡ **FLAG Encontrada!** ⚡

Digitando no app:

![](images/28.png)

---

## Conclusão

Você aprendeu como:

| Técnica                                  | Objetivo                                         |
| ---------------------------------------- | ------------------------------------------------ |
| Hookar funções nativas com `Interceptor` | Instrumentar binários `.so`                      |
| Encontrar endereços com `Module.*` APIs  | Localizar símbolos exportados                    |
| Ler strings de memória                   | Dump de argumentos com `Memory.readUtf8String()` |
| Reduzir ruído                            | Filtrar chamadas específicas                     |

Esse tipo de abordagem é crucial em:

✔ Crackmes Android com NDK
✔ Proteções de anti-debug / anti-tamper
✔ Verificação lógica no nível nativo
✔ Root detection bypass
