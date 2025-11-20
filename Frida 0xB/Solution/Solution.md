
## Pré-requisitos

* Básico de Engenharia Reversa usando JADX.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.
* Conhecimentos básicos de assembly x86/ARM64 e reversing.

## Desafio 0xB

O objetivo principal deste desafio é introduzir **patching temporário de instruções** usando Frida.

Começamos instalando e abrindo o app:

![](images/1.png)

A interface não apresenta nada interessante. Ao clicar no botão, nada acontece.

Vamos ao JADX:

![](images/2.png)

No início vemos a declaração da função nativa `getFlag()`:

![](images/3.png)

No final, a biblioteca nativa `frida0xb.so` é carregada com **System.loadLibrary**.

No método `onCreate`, `getFlag()` é chamado:

* sem argumentos
* sem valor de retorno

Vamos então analisar a biblioteca nativa no Ghidra.
Extraímos o APK e selecionamos a lib x86 (pois o emulador é x86).

![](images/4.png)

Carregamos a biblioteca no Ghidra:

![](images/5.png)

Analisamos a função `getFlag()`:

![](images/6.png)

A decompilação não parece fazer sentido:

![](images/7.png)

Mas o motivo fica claro no **disassembly**:

![](images/8.png)

Resumo:

1. `0xdeadbeef` é movido para `local_14`
2. É comparado com `0x539`
3. Como nunca serão iguais, Ghidra otimiza removendo o bloco de código dependente do `if`

Fluxo em gráfico:

![](images/9.png)
![](images/10.png)

Para ver a lógica original, desativamos otimizações no Ghidra:

Edit → Tool Options

![](images/11.png)
![](images/12.png)

Desmarque **Eliminate unreachable code**:

![](images/13.png)

Agora vemos que o código originalmente:

* compara `local_14 == 1337`
* decodifica a string `j~ehmWbmxezisdmogi~Q` com XOR `0x2c`
* registra a flag no log

Mas como o `if` nunca é verdadeiro, nada é exibido.

---

## Estratégia

Precisamos **desativar o salto condicional** que impede a execução do bloco que revela a flag.

Vamos aplicar um patch temporário:

* substituir `JNZ` por instruções `NOP` no código nativo

Para isso usamos **X86Writer** (já que estamos em x86).

Modelo básico:

```javascript
var writer = new X86Writer(<address>);

try {
    writer.flush();
} finally {
    writer.dispose();
}
```

---

## Identificando o ponto a ser alterado

Trecho crítico:

```asm
00020e1c  MOV [EBP + local_14], 0xdeadbeef
00020e23  CMP [EBP + local_14], 0x539
00020e2a  JNZ LAB_00020f08
```

Se JNZ for executado, a execução pula para o final → sem flag.
Precisamos **NOPar o JNZ**.

Endereço da lib em execução:

```
Module.getBaseAddress("libfrida0xb.so")
"0xc2083000"
```

Offset do JNZ:

```
0x20e2a - 0x00010000 = 0x10e2a
```

Endereço real:

```
0xc2083000 + 0x10e2a = 0xc2093e2a
```

---

## Primeiro patch (ainda sem sucesso)

```javascript
var jnz = Module.getBaseAddress("libfrida0xb.so").add(0x20e2a - 0x10000);
var writer = new X86Writer(jnz);

try {
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.flush();
} finally {
    writer.dispose();
}
```

Resultado:

![](images/17.png)

O processo caiu com **memory protection fault**
(x86 `.text` é RX, não WRX)

Podemos confirmar pelo mapa de memória:

![](images/18.png)

---

## Aplicando permissões de escrita

Usamos `Memory.protect()`:

```
Memory.protect(jnz, 0x1000, "rwx");
```

Script final:

```javascript
var jnz = Module.getBaseAddress("libfrida0xb.so").add(0x20e2a - 0x10000);
Memory.protect(jnz, 0x1000, "rwx");
var writer = new X86Writer(jnz);

try {
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.putNop();
    writer.flush();
} finally {
    writer.dispose();
}
```

Executando:

![](images/19.png)
![](images/20.png)
![](images/21.png)

Flag obtida. Patch bem-sucedido.

---

## ARM64

No ARM64:

```asm
subs w8, w8, #0x539
b.ne LAB_0011532c
```

Queremos o oposto:

* trocar `b.ne` por `b` que **ignora os flags**
* branch direto para o próximo endereço

Usando `Arm64Writer`:

```javascript
var adr = Module.findBaseAddress("libfrida0xb.so").add(0x15248);
Memory.protect(adr, 0x1000, "rwx");
var writer = new Arm64Writer(adr);
var target = Module.findBaseAddress("libfrida0xb.so").add(0x1524c);

try {
    writer.putBImm(target);
    writer.flush();
} finally {
    writer.dispose();
}
```

Execução:

![](images/26.png)
![](images/27.png)

Flag revelada no log.

---

## Conclusão

O desafio demonstrou:

| Técnica                     | Objetivo                                       |
| --------------------------- | ---------------------------------------------- |
| `X86Writer` / `Arm64Writer` | Inserir instruções nativas em runtime          |
| `Memory.protect()`          | Manter execução sem crash ao escrever na .text |
| Alteração de fluxo          | Bypass de validações lógicas em código nativo  |

Essa técnica é fundamental para:

* contornar verificações de segurança
* estudar lógica interna protegida
* análises mais profundas de bibliotecas nativas