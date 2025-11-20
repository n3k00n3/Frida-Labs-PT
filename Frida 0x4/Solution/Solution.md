
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x4

Vamos dar uma olhada no APK do desafio:

![](images/1.png)

Praticamente nada acontecendo na interface. Vamos ver a descompilação.

![](images/2.png)

Nada útil na `MainActivity`.
Então vamos inspecionar a classe `Check`.

![](images/3.png)

Podemos ver um método chamado `get_flag`.
Ele realiza uma operação simples de **XOR** para decodificar o texto:

```
I]FKNtW@]JKPFA\\[NALJr
```

Usando a chave:

```
15
```

Sim, seria fácil descriptografar estáticamente — mas o objetivo aqui é **treinar Frida** 🎯

Observações importantes:

* O método **não é chamado** em nenhum lugar do app
* A função verifica se o argumento `a == 1337`
* Se a condição for satisfeita → retorna a FLAG

Portanto: basta **invocar esse método com 1337 usando Frida**
Já fizemos algo parecido antes, mas aquela era uma função **estática**
Desta vez, **precisamos instanciar a classe** antes de chamar o método.

---

## Chamando o método `get_flag()` com Frida

Exemplo de como isso seria feito em Java nativamente:

```java
Check ch = new Check();
String flag = ch.get_flag(1337);
```

Ou seja:

✔ Criar objeto
✔ Chamar método
✔ Capturar retorno (String)

---

Estrutura base em Frida:

```javascript
Java.perform(function() {

  var <class_reference> = Java.use("<pacote>.<classe>");
  var <instancia> = <class_reference>.$new(); // Cria objeto
  <instancia>.<metodo>(); // Chama o método

});
```

 `$new()` é um método especial do Frida utilizado para instanciar classes Java.

---

Agora, aplicando ao nosso desafio:

* Pacote: `com.ad2001.frida0x4`
* Classe: `Check`
* Método: `get_flag(int a)`

### Script Final:

```javascript
Java.perform(function() {

  var check = Java.use("com.ad2001.frida0x4.Check");
  var check_obj = check.$new(); // Instância da classe
  var res = check_obj.get_flag(1337); // Invocando o método

  console.log("FLAG: " + res);

});
```

---

### Execução:

```bash
frida -U -f com.ad2001.frida0x4
```

Cole o script no console:

![](images/4.png)

---

Sucesso! Flag obtida com Frida!

---

## Conclusão

Neste desafio você aprendeu:

| Habilidade                       | Descrição                    |
| -------------------------------- | ---------------------------- |
| Instanciar classes Java no Frida | Usando `$new()`              |
| Invocar métodos não estáticos    | Passando argumentos corretos |
| Capturar valores de retorno      | Logs via `console.log()`     |

Continuamos ampliando o arsenal para engenharia reversa dinâmica em Android 
