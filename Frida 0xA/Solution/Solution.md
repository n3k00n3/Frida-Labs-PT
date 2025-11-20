
## Pré-requisitos

* Básico de Engenharia Reversa usando JADX.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.
* Conhecimentos básicos de assembly x86/ARM64 e reversing.

## Desafio 0xA

Vamos começar instalando o aplicativo.

![](images/1.png)

Como sempre, vamos abrir no JADX.

![](images/2.png)

Este APK é muito parecido com os anteriores, porém desta vez o app foi desenvolvido em Kotlin.
No final do arquivo podemos ver o carregamento da biblioteca nativa:

```java
static {
    System.loadLibrary("frida0xa");
}
```

Também há um método JNI declarado:

![](images/3.png)

Esse método retorna uma string. O app chama esse método da biblioteca `frida0xa.so` e define o seu retorno no `TextView`, exibindo o texto "Hello Hackers" ao iniciar o aplicativo.

Vamos decompilar o APK com apktool e examinar a biblioteca:

![](images/4.png)

Agora, vamos abrir essa biblioteca no Ghidra:

![](images/5.png)

Análise concluída. Vamos inspecionar as funções:

![](images/6.png)

Temos duas funções principais:

* `get_flag()`
* `Java_com_ad2001_frida0xa_MainActivity_stringFromJNI()`

Como visto, é o método `stringFromJNI()` que define o texto inicial no TextView:

![](images/7.png)

Agora vamos analisar a função `get_flag()`:

* Não está declarada no código Java/Kotlin
* Não é chamada em nenhum lugar da aplicação
* É apenas referenciada pela tabela FDE

![](images/8.png)
![](images/9.png)

Decompilação da função:

![](images/10.png)

A função recebe dois inteiros, soma e verifica se o resultado é igual a `3`. Caso seja, executa um loop que decodifica a string `FPE>9q8A>BK-)20A-#Y` e registra a flag no log.

Conclusão: Para obter a flag precisamos chamar essa função manualmente.

Vamos usar Frida para isso.

---

## Chamando a função nativa com Frida

Modelo básico:

```javascript
var native_adr = new NativePointer(<address>);
const native_function = new NativeFunction(native_adr, '<return type>', ['argument_types']);
native_function(<arguments>);
```

Explicação:

1. Criamos um `NativePointer` apontando para o endereço da função
2. Criamos um `NativeFunction`, informando:

   * endereço do ponteiro
   * tipo de retorno da função
   * tipos dos argumentos
3. Chamamos como uma função comum

---

### Encontrando o endereço da função

Vamos iniciar o Frida para obter o endereço base da lib:

```
frida -U -f com.ad2001.frida0xa
```

```
Module.getBaseAddress("libfrida0xa.so")
"0xc1859000"
```

Agora, no Ghidra verificamos o offset:

![](images/11.png)

Base usada pelo Ghidra:

![](images/12.png)
![](images/13.png)

Cálculo:

```
Offset = 0x00028BB0 - 0x00010000 = 0x18BB0
```

Somando base real + offset:

```
Module.getBaseAddress("libfrida0xa.so").add(0x18BB0)
// 0xc1871bb0
```

Endereço obtido com sucesso.

---

### Script final

```javascript
var adr = Module.findBaseAddress("libfrida0xa.so").add(0x18BB0);
var get_flag_ptr = new NativePointer(adr);
const get_flag = new NativeFunction(get_flag_ptr, 'void', ['int', 'int']);
get_flag(1, 2);
```

Justificativa:
O `if` na função verifica:

```c
param_1 + param_2 == 3
```

Portanto, argumentos `1` e `2` são suficientes.

---

### Execução

![](images/14.png)
![](images/15.png)

Verificando o log:

![](images/16.png)

Flag obtida com sucesso.
