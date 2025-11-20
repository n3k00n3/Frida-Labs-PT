
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x5

Vamos iniciar nosso desafio. Espero que você já tenha instalado o aplicativo.

![](images/1.png)

Assim como nos desafios anteriores, não há muita coisa na interface.
Vamos ver no JADX o que realmente está acontecendo.

![](images/2.png)

Na `MainActivity`, existe um método chamado `flag` que **não é chamado em lugar nenhum** do código.
Esse método descriptografa a flag e define ela no TextView.

Observe também que precisamos passar o valor **1337** como argumento para satisfazer o `if`.

Situação parecida com o desafio anterior, mas… agora o método está na própria `MainActivity`.

💡 Ideia inicial: criar uma **nova instância** de `MainActivity` e chamar o método.
→ Vamos testar!

* Nome do pacote: `com.ad2001.frida0x5`
* Classe: `MainActivity`
* Método: `flag`

Template que vimos anteriormente:

```javascript
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  var <class_instance> = <class_reference>.$new(); // Instância da classe
  <class_instance>.<method>(); // Chamando método

});
```

Tentativa inicial:

```javascript
Java.perform(function() {

  var a = Java.use("com.ad2001.frida0x5.MainActivity");
  var main_act = a.$new();
  main_act.flag(1337);

});
```

---

Vamos rodar:

```
frida -U -f com.ad2001.frida0x5
```

![](images/3.png)

Crash!

---

### Por que isso acontece?

Criar diretamente uma instância de **Activity** no Frida não é viável porque:

| Motivo                | Explicação                                       |
| --------------------- | ------------------------------------------------ |
| Contexto inexistente  | Activities dependem de `Context` real            |
| Thread errada         | UI exige o **main thread** com `Looper` ativo    |
| Ciclo de vida Android | O sistema deve gerenciar instâncias corretamente |

Conclusão: **Não** é uma boa ideia instanciar `MainActivity` manualmente.

---

## Solução correta

Quando o aplicativo inicia, o Android cria uma instância válida de `MainActivity`.

Vamos simplesmente **localizar e reutilizar essa instância existente**!

Frida permite isso com:

| API               | Função                                 |
| ----------------- | -------------------------------------- |
| `Java.performNow` | Executa imediatamente no contexto Java |
| `Java.choose`     | Enumera instâncias de uma classe       |

Template

```javascript
Java.performNow(function() {
  Java.choose('<Package.Classe>', {
    onMatch: function(instance) {
      // instância encontrada
    },
    onComplete: function() {}
  });
});
```

---

Agora adaptando para nosso caso:

```javascript
Java.performNow(function() {
  Java.choose('com.ad2001.frida0x5.MainActivity', {
    onMatch: function(instance) {
      console.log("Instance found");
    },
    onComplete: function() {}
  });
});
```

Rodando:

```
frida -U -f com.ad2001.frida0x5
```

![](images/4.png)

Observação importante:

> Em alguns emuladores, isso pode causar crash de VM por falha interna — não é seu script!

Recomendações:

✔ Testar em dispositivo físico
✔ Usar versão mais recente do Frida
✔ Trocar de emulador caso necessário

Exemplo de funcionamento correto:

![](images/5.png)

Instância encontrada ✔

---

## Chamando `flag(1337)` na instância real

Basta completar o callback:

```javascript
Java.performNow(function() {
  Java.choose('com.ad2001.frida0x5.MainActivity', {
    onMatch: function(instance) {
      console.log("Instance found");
      instance.flag(1337); // Chama o método!
    },
    onComplete: function() {}
  });
});
```

Executamos novamente…

![](images/6.png)

FLAG exibida no TextView!

---

## Conclusão

Neste desafio você aprendeu:

| Técnica                                  | Uso                                  |
| ---------------------------------------- | ------------------------------------ |
| Enumerar instâncias de classe            | `Java.choose()` para Activities      |
| Executar no main thread                  | `Java.performNow()`                  |
| Invocar métodos de Activities existentes | Interagindo com o ciclo de vida real |

Agora você já é capaz de:

✔ localizar objetos em runtime
✔ chamar métodos reais da interface
✔ manipular a execução sem crashar o app 

