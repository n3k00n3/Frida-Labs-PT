
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Proficiência em leitura e entendimento de código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x3

Vamos começar com nosso APK. Primeiro instalamos a aplicação e observamos como ela funciona:

![](Images/1.png)

A aplicação possui um botão e um TextView.
O TextView fornece uma dica sobre a flag.
Não há campos de entrada (EditText).

Quando clicamos no botão → aparece **"TRY AGAIN"**.
Então, vamos para a engenharia reversa com JADX.

Carregando no jadx:

![](Images/2.png)

Dessa vez temos uma classe extra. Vamos observar a classe `Checker`.

![](Images/3.png)

Nesta classe:

* Existe uma variável estática inteira chamada `code` inicializada em **0**
* Existe um método estático `increase()`

Este método simplesmente **adiciona 2** ao valor de `code` quando chamado.
Mas ele **não é chamado em nenhum ponto** da aplicação → logo, `code` nunca muda.

Agora vamos inspecionar o código da `MainActivity`:

```java
btn.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x3.MainActivity.1
    @Override
    public void onClick(View v) {
        if (Checker.code == 512) {
            ...
            ...
            ...
        }
        ...
    }
});
```

Resumo da lógica:

| Condição              | Resultado no app                                |
| --------------------- | ----------------------------------------------- |
| `Checker.code == 512` | Mostra “You won”, descriptografa a FLAG e exibe |
| Senão                 | Mostra “TRY AGAIN”                              |

---

Existem **duas maneiras** de resolver:

- Alterar diretamente o valor da variável `code` para **512**
- Chamar o método `increase()` **256 vezes**

Vamos ver as duas soluções com Frida 

---

## Método 1 — Alterando o valor da variável `code`

Trecho original no APK:

```java
public class Checker {
    static int code = 0;

    public static void increase() {
        code += 2;
    }
}
```

Template para alterar variáveis estáticas com Frida:

```javascript
Java.perform(function (){

    var <class_reference> = Java.use("<package>.<classe>");
    <class_reference>.<variável>.value = <valor>;

})
```

Aplicando ao caso:

```javascript
Java.perform(function (){

    var a = Java.use("com.ad2001.frida0x3.Checker");
    a.code.value = 512;

})
```

Executando:

```bash
frida -U -f com.ad2001.frida0x3
```

![](Images/4.png)

Antes do script → “TRY AGAIN”

Após injetar → clique no botão:

![](Images/5.png)

E…

![](Images/6.png)

 FLAG encontrada com sucesso!

---

## Método 2 — Chamando `increase()` 256 vezes

Cada execução de `increase()`:

```
code += 2
```

Então:

```
2 × 256 = 512  → condição satisfeita
```

Script:

```javascript
Java.perform(function () {
    var a = Java.use("com.ad2001.frida0x3.Checker");

    for (var i = 1; i <= 256; i++) {
        console.log("Calling increase() method " + i + " times");
        a.increase();
    }
});
```

Novamente:

```bash
frida -U -f com.ad2001.frida0x3
```

Cole o script no console:

![](Images/7.png)

Ele irá chamar a função repetidamente:

![](Images/8.png)

Clique no botão e…

![](Images/9.png)

 FLAG obtida novamente!

---

## Conclusão

Você aprendeu mais duas técnicas fundamentais com Frida:

| Técnica                     | Aplicação                      |
| --------------------------- | ------------------------------ |
| Alterar variáveis estáticas | Bypass de verificações simples |
| Invocar métodos estáticos   | Manipular lógica da aplicação  |

Essas habilidades serão muito úteis nos próximos desafios 

