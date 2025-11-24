// server.js

//تضمين المكتبات المراد استخدامها 
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');

require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

// مفتاح JWT 
const JWT_SECRET = process.env.JWT_SECRET;

// تحقق من ان سيرفر شغال 
app.get('/health', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    res.json({ status: 'OK', db: 'MySQL', ok: rows[0].ok });
  } catch (e) {
    res.status(500).json({ status: 'DB_ERROR', error: e.message });
    console.log(e.message)
  }
});

//   تسجيل حساب جديد (Sign UP) 
app.post('/auth/register', async (req, res) => {

  const { national_id, phone, password, confirm_password } = req.body;
  
  console.log(national_id);
  console.log(phone);
  console.log(password);
  console.log(confirm_password);

  //  التحقق من الحقول
  if (!national_id || !phone || !password || !confirm_password) {
    return res.status(400).json({ message: "ادخل جميع الحقول مطلوبة" });
  }

  try {
    // التحقق من وجود المواطن في السجل المدني
    const [civil] = await pool.execute(
      "SELECT * FROM person_card WHERE national_id = ?",
      [national_id]
    );

    if (civil.length === 0) {
      return res.status(404).json({ message: "المواطن غير موجود في السجل المدني" });
    }

    // التحقق من أنّ رقم الهاتف ملك لنفس المواطن
    const [telecom] = await pool.execute(
      "SELECT * FROM telecom_company WHERE phone_number = ? AND national_id = ?",
      [phone, national_id]
    );

    if (telecom.length === 0) {
      return res.status(400).json({ message: "هذا الرقم ليس مسجلاً باسمك" });
    }

    // التحقق إن كان لديه حساب مسبقًا
    const [users] = await pool.execute(
      "SELECT * FROM users WHERE national_id = ?",
      [national_id]
    );

    if (users.length > 0) {
      return res.status(400).json({ message: "المستخدم مسجل مسبقًا" });
    }

    // التحقق من تطابق كلمة المرور
    if (password !== confirm_password) {
      return res.status(400).json({ message: "كلمة المرور غير متطابقة" });
    }

    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);

    // إنشاء المستخدم
    await pool.execute(
      "INSERT INTO users (national_id, password_hash) VALUES (?, ?)",
      [national_id, hashedPassword]
    );

    // نتيجة النجاح
    return res.json({ message: "تم إنشاء الحساب بنجاح، قم الان بتسجيل الدخول" });

    console.log("Sign UP Done");

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "خطأ في الخادم" });
  }
});


// تسجيل الدخول (Sign IN) 
app.post('/auth/login', async (req, res) => {

  const { national_id, password } = req.body;

  if (!national_id || !password) {
    return res.status(400).json({ message: "مطلوب الرقم الوطني وكلمة المرور" });
  }

  try {
    const [users] = await pool.execute("SELECT * FROM users WHERE national_id = ?", [national_id]);
    if (users.length === 0) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "كلمة المرور غير صحيحة" });
    }

    // توليد رمز تحقق OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.execute("UPDATE users SET otp_code = ?, otp_created_at = NOW() WHERE national_id = ?", [otp, national_id]);

    // إنشاء JWT
    const token = jwt.sign({ national_id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: "تم تسجيل الدخول ناجح - تم إرسال رمز التحقق", token, otp}); // otp مؤقتًا للعرض

    console.log("Sign IN Done");
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في الخادم" });
  }
});

// التحقق من الرمز (Verify OTP) 
app.post('/auth/verify-otp', async (req, res) => {

  const { otp } = req.body;

  if (!otp) {
    return res.status(400).json({ message: "!مطلوب رمز التحقق" });
  }

  try {
    // البحث عن المستخدم الذي يملك هذا الرمز
    const [users] = await pool.execute("SELECT * FROM users WHERE otp_code = ?", [otp]);

    if (users.length === 0) {
      return res.status(400).json({ message: "!رمز التحقق غير صحيح أو منتهي الصلاحية" });
    }

    const user = users[0];

    // (اختياري) تحقق من أن الرمز لم يمر عليه أكثر من 5 دقائق مثلاً
    const otpCreatedAt = new Date(user.otp_created_at);
    const now = new Date();
    const diffMinutes = (now - otpCreatedAt) / 1000 / 60;

    if (diffMinutes > 2) {
      return res.status(400).json({ message: "انتهت صلاحية رمز التحقق، يرجى طلب رمز جديد" });
    }

    res.json({
      message: "تم التحقق بنجاح ✅",
      national_id: user.national_id
    });

    console.log("Verify Done");
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في الخادم" });
  }
});


//  إعادة إرسال رمز التحقق  (Resend OTP) 
app.post('/auth/resend-otp', async (req, res) => {

  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.execute("UPDATE users SET otp_code = ?, otp_created_at = NOW() WHERE national_id = ?", [otp, decoded.national_id]);

    res.json({ message: "تم إرسال رمز جديد", otp });
    console.log("resend Done");
    
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

//تابع لتحويل مسار الصورة الى رابط URL 
  function buildUrl(req, filePath) {
    if (!filePath) return null;
    const clean = filePath.replace(/^\.*\//, "");
    return `${req.protocol}://${req.get("host")}/${clean}`;
  }


// جلب بيانات البطاقة الشخصية (Get Person Card Info) 
app.get('/person-card', async (req, res) => {

  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وُجدت
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
 
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await pool.execute(
      "SELECT * FROM person_card WHERE national_id = ? LIMIT 1",
      [decoded.national_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات الهوية" });
    }

    const card = rows[0];

    // نسخ كل الحقول مرة واحدة
    let cardData = { ...card };

    // تحويل مسار الصورة الى رابط URL من اجل جلب الصور والوصول اليها عبر الاستضافة
    // اكتب فقط اسماء اعمدة الصور في جدول
    cardData.profile_image_url = buildUrl(req, card.profile_image_path);
    cardData.front_image_url   = buildUrl(req, card.front_image);
    cardData.back_image_url    = buildUrl(req, card.back_image);

    // اختياري: حذف المسارات الأصلية
    // delete cardData.profile_image_path;
    // delete cardData.front_image;
    // delete cardData.back_image;

    return res.json({message: "تم جلب بيانات هويتك الشخصية", card: cardData });

    console.log("Person Card information was obtained");


  } catch (err) {
    console.error("JWT Error:", err.message);
    return res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

// جلب بيانات رخصة القيادة (Get Driving license Info) 
app.get('/driving-license', async (req, res) => {

  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وجدت
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await pool.execute(
      "SELECT * FROM driving_licenses WHERE national_id = ? LIMIT 1",
      [decoded.national_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات الرخصة" });
    }

    const license = rows[0];

    // نسخ كل الحقول مرة واحدة
    let licenseData = { ...license };

    // تحويل مسار الصورة الى رابط URL من اجل جلب الوصول اليها عبر الاستضافة
    // اكتب فقط اسماء اعمدة الصور في جدول
    licenseData.front_image_url  = buildUrl(req, license.front_image_driver);
    licenseData.back_image_url   = buildUrl(req, license.back_image_driver);

    // حذف المسارات الأصلية (اختياري)
    // delete licenseData.front_image;
    // delete licenseData.back_image;

    return res.json({message: "تم جلب بيانات رخصتك", license: licenseData });

    console.log("Driving license information was obtained");


  } catch (err) {
    console.error("JWT Error:", err.message);
    return res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

// جلب بيانات جواز السفر (Get Passport Info) 
app.get('/passport', async (req, res) => {

  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وُجدت
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await pool.execute(
      "SELECT * FROM passport WHERE national_id = ? LIMIT 1",
      [decoded.national_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات جواز السفر" });
    }

    const passport = rows[0];

    // نسخ كل الحقول مرة واحدة
    let passportData = { ...passport };

    return res.json({ passport: passportData });

    console.log("Passport information was obtained")

  } catch (err) {
    console.error("JWT Error:", err.message);
    return res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

// تصدير معلومات الهوية الى صيغة PDF 
app.get('/export/person-card/pdf', async (req, res) => {
  
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وُجدت
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(authHeader, JWT_SECRET);

    const [rows] = await pool.execute(
      "SELECT * FROM person_card WHERE national_id = ?",
      [decoded.national_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات البطاقة" });
    }

    const card = rows[0];

    // إعداد الهيدرز الصحيحة
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="person_card_${card.national_id}.pdf"`);

    const doc = new PDFDocument();
    
    doc.pipe(res);

    // أضف نصوص وحقول من الهوية
    doc.fontSize(16).text("Person Card", { underline: true });
    
    doc.moveDown();
    doc.fontSize(12).text(`National_id: ${card.national_id}`);
    doc.text(`Full Name: ${card.first_name} ${card.father_name} ${card.last_name}`);
    doc.text(`Full Name: ${card.birth_date}`);
    doc.text(`ID number: ${card.id_number}`);
    // أضف المزيد من المعلومات للملف

    doc.end();
    
  } catch (err) {
    console.error("PDF Error:", err);
    res.status(500).json({ message: "خطأ في إنشاء PDF" });
  }
});

// توليد كود الاستجابة السريع للهوية QR 
app.get('/generate-qr', async (req, res) => {

  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وُجدت
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const nationalId = decoded.national_id;

    // المحتوى الذي تريد ترميزه في QR
    const qrData = JSON.stringify({ national_id: nationalId });

    // توليد QR كـ data URL (base64 PNG)
    const qrCodeDataUrl = await QRCode.toDataURL(qrData, { errorCorrectionLevel: 'H' });

    // إرسال data URL إلى العميل
    res.json({ qrCode: qrCodeDataUrl });
    

  } catch (err) {
    return res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

//--------------------------------------للواجهات الديناميكية، للمشروع التخرج-------------------------------
// جلب البطاقات (Get Cards)
app.get('/citizen/cards', async (req, res) => {

  const token = req.headers['authorization']?.replace("Bearer ", "");

  if (!token) {
      return res.status(400).json({ message: "مطلوب التوكن" });
  }

  try {
      const decoded = jwt.verify(token, JWT_SECRET);

       const [rows] = await pool.execute(
          "SELECT * FROM citizen_documents WHERE national_id = ? AND document_type = 'card'",
          [decoded.national_id]
      );

      const baseUrl = `${req.protocol}://${req.get('host')}`;

      const cards = rows.map(card => {
          let path = card.document_image_path;

          if (path && !path.startsWith('/')) {
              path = '/' + path;
          }

          return {
              ...card,
              document_image_url: path ? `${baseUrl}${path}` : null
          };
      });

      return res.json({ message: "تم جلب البطاقاتك", cards });

      console.log("Get Cards Done");

  } catch (error) {
      console.error(error);
      return res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

//  8. جلب المستندات (Get Documents)
app.get('/citizen/documents', async (req, res) => {

  const token = req.headers['authorization']?.replace("Bearer ", "");

  if (!token) return res.status(400).json({ message: "مطلوب التوكن" });

  try {
      const decoded = jwt.verify(token, JWT_SECRET);
    
      const [rows] = await pool.execute(
          "SELECT * FROM citizen_documents WHERE national_id = ? AND document_type = 'document'",
          [decoded.national_id]
      );

      res.json({message: "تم جلب مستنداتك", documents: rows });

      console.log("Get Documents Done");

  } catch (error) {
      res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});
//----------------------------------------------------------------------------

// تشغيل السيرفر
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000/health');
});

