
## Pré-requisitos

* Básico de Engenharia Reversa usando jadx.
* Capacidade de entender código Java.
* Capacidade de escrever pequenos trechos em JavaScript.
* Familiaridade com adb.
* Dispositivo com root.

## Desafio 0x6

Vamos começar instalando o APK e abrindo-o:

![](images/1.png)

Assim como nos desafios anteriores… não temos nada na interface.
Vamos ao JADX para descobrir o que está acontecendo:

![](images/2.png)

Aqui temos um cenário que já vimos antes:

O método `get_flag()`:

* **não é chamado** em nenhum lugar
* descriptografa a flag usando **AES**
* define a flag no TextView
* recebe **um argumento** do tipo `Checker`

Declaração do método:

```java
public void get_flag(Checker A) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Method body
}
```

Dentro do método, ele verifica:

```java
A.num1 == 1234 && A.num2 == 4321
```

Se essa condição for verdadeira → a flag é descriptografada e exibida.

Vamos então observar a classe `Checker`:

![](images/3.png)

Ela contém duas variáveis públicas:

* `num1`
* `num2`

Precisamos configurar os valores:

| Variável | Valor necessário |
| -------- | ---------------- |
| num1     | 1234             |
| num2     | 4321             |

E não existe instância dessa classe sendo criada no app.

---

## Solução

Isso é **bem simples**, pois já fizemos algo parecido no Desafio 0x5.

Passos:

1️⃣ Criar uma instância da classe `Checker`
2️⃣ Definir `num1 = 1234` e `num2 = 4321`
3️⃣ Obter a instância existente da `MainActivity`
4️⃣ Invocar `get_flag(checker_obj)`

---

### Script Frida completo

Primeiro criamos o objeto da classe `Checker`:

```javascript
var checker = Java.use("com.ad2001.frida0x6.Checker");
var checker_obj = checker.$new();
```

Alteramos os valores das variáveis:

```javascript
checker_obj.num1.value = 1234;
checker_obj.num2.value = 4321;
```

Agora obtemos a instância da `MainActivity` já criada pelo Android:

```javascript
Java.performNow(function() {
  Java.choose('com.ad2001.frida0x6.MainActivity', {
    onMatch: function(instance) {
      console.log("Instance found");
    },
    onComplete: function() {}
  });
});
```

Agora vamos **unir tudo**:

```javascript
Java.performNow(function() {
  Java.choose('com.ad2001.frida0x6.MainActivity', {
    onMatch: function(instance) {
      console.log("Instance found");

      var checker = Java.use("com.ad2001.frida0x6.Checker");
      var checker_obj  = checker.$new();
      checker_obj.num1.value = 1234;
      checker_obj.num2.value = 4321;

      instance.get_flag(checker_obj);
    },
    onComplete: function() {}
  });
});
```

---

Executando no Frida:

```bash
frida -U -f com.ad2001.frida0x6
```

![](images/4.png)

Agora basta olhar o app:

<img src="images/5.jpg" style="zoom:5%;" />

 FLAG CAPTURADA COM SUCESSO!

---

## Conclusão

Neste desafio você aprendeu:

| Habilidade                                 | Para quê serve                                  |
| ------------------------------------------ | ----------------------------------------------- |
| Criar instância de classe                  | Produzir objetos necessários que o app não cria |
| Manipular atributos internos               | Satisfazer verificações no fluxo do app         |
| Invocar métodos com objetos personalizados | Forçar execução de lógica oculta                |
| Localizar instâncias de atividades         | Integrar com ciclo de vida real                 |

Agora você já sabe:

✔ Invocar métodos com objetos como argumento
✔ Modificar valores internos para burlar validações
✔ Combinar técnicas para desbloquear lógica criptografada

