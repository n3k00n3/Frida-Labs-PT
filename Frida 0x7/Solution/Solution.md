
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x7

Este desafio é semelhante ao **Challenge 0x5**, porém com uma diferença importante:

Aqui vamos aprender a **hookar um construtor**

Primeiro, instalamos e abrimos o APK:

![](images/1.png)

Sim… nosso clássico **Hello World!** 
Vamos abrir no JADX:

![](images/2.png)

Podemos observar um padrão muito parecido com os desafios anteriores:

* O método `flag()` existe
* Ele é **chamado** no código
* Porém, os valores nos atributos não satisfazem o `if` → nenhuma flag aparece

Vamos olhar a classe `Checker`:

![](images/3.png)

Aqui temos um **construtor** que recebe dois inteiros:

* Eles são armazenados em `num1` e `num2`
* E para passar na verificação, ambos devem ser **maiores que 512**

```java
public void flag(Checker A) {
    if (A.num1 > 512 && 512 < A.num2) {
        // FLAG!!
    }
}
```

---

## Primeira solução (mais simples)

Criamos um objeto `Checker` com valores válidos e chamamos `flag()`:

```javascript
var checker_obj = checker.$new(600, 600);
```

Script completo:

```javascript
Java.performNow(function() {
  Java.choose('com.ad2001.frida0x7.MainActivity', {
    onMatch: function(instance) {
      console.log("Instance found");

      var checker = Java.use("com.ad2001.frida0x7.Checker");
      var checker_obj  = checker.$new(600, 600);
      instance.flag(checker_obj);
    },
    onComplete: function() {}
  });
});
```

Rodando o script, a flag é exibida:

<img src="images/4.jpg" style="zoom:25%;" />

Fácil demais, né?

Mas agora vamos ao objetivo real do desafio…

---

## Hookando o Construtor

> **Atenção:** Esse método não funciona em ARM64
> Referência: [https://github.com/frida/frida/issues/1575](https://github.com/frida/frida/issues/1575)

Hookar um construtor é parecido com hookar qualquer método:

Usamos o nome: `$init`

Template:

```javascript
Java.perform(function() {
  var <class_ref> = Java.use("<package>.<Classe>");
  <class_ref>.$init.implementation = function(<args>) {
    // Nosso código
  }
});
```

Aplicando ao nosso caso:

```javascript
Java.perform(function() {
  var a = Java.use("com.ad2001.frida0x7.Checker");
  a.$init.implementation = function(param) {

    // Substituímos os valores recebidos por valores válidos
    this.$init(600, 600);
  }
});
```

---

### Execução

Como `Checker` é instanciado dentro do `onCreate()`:

✔ O construtor será executado logo no início da aplicação
✔ Portanto, precisamos **injetar o script no spawn do app**

```bash
frida -U -f com.ad2001.frida0x7 -l hook.js
```

Resultado:

<img src="images/5.jpg" style="zoom:25%;" />

FLAG obtida via hook do construtor!

---

## Conclusão

Neste desafio você aprendeu:

| Conceito                             | O que aprendeu                                       |
| ------------------------------------ | ---------------------------------------------------- |
| Hookar construtores                  | `$init.implementation`                               |
| Modificar atributos já no construtor | Mudando valores antes do app usar                    |
| Interceptação durante instanciamento | O app chama o construtor → você muda o comportamento |

Agora você está pronto para manipular criação de objetos e lógica do app **desde o começo da execução** 
