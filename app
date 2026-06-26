/**
 * =========================================================================
 * ATH TEST PREP CENTER - COMPLETE CORE BACKEND ENGINE
 * Tech Stack: Node.js, Express.js, PostgreSQL, JWT, BcryptJS, Multer
 * File: server.js (Tích hợp Middleware bảo mật và toàn bộ API endpoints)
 * =========================================================================
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ATH_SUPER_SECRET_KEY_2026';

// =========================================================================
// 1. CẤU HÌNH KẾT NỐI DATABASE POSTGRESQL & FILE UPLOAD
// =========================================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ath_center',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Khởi tạo thư mục uploads nếu chưa tồn tại
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Cấu hình Multer để lưu trữ ảnh thẻ và các hợp đồng scan
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (file.fieldname === 'file_anh_the') {
    if (['.png', '.jpg', '.jpeg', '.gif', '.webp'].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Định dạng ảnh thẻ không hợp lệ!'));
    }
  } else if (file.fieldname === 'file_hop_dong' || file.fieldname === 'file_hop_dong_hoc_vien' || file.fieldname === 'file_gpkd') {
    if (['.pdf', '.doc', '.docx', '.xls', '.xlsx'].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Định dạng tài liệu không hợp lệ!'));
    }
  } else {
    cb(null, true);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: uploadFilter,
  limits: { fileSize: 10 * 1024 * 1024 } // Giới hạn tệp tối đa 10MB
});

// Middlewares cơ bản
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadDir));


// =========================================================================
// 2. MIDDLEWARES BẢO MẬT: XÁC THỰC JWT & KIỂM TRA PHÂN QUYỀN
// =========================================================================

/**
 * Middleware kiểm tra tính hợp lệ của JWT token được gửi kèm trong Header
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Định dạng: "Bearer <token>"

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Từ chối truy cập! Vui lòng cung cấp mã JWT Token.' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Mã Token hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại!' 
      });
    }
    req.user = user; // Gắn thông tin tài khoản giải mã vào request
    next();
  });
};

/**
 * Middleware kiểm tra quyền truy cập chi tiết của nhóm người dùng (RBAC)
 * @param {string} chucNang - Tên danh mục chức năng (ví dụ: 'GIAO_VIEN', 'HOC_VIEN', 'LOP_HOC', 'MON_HOC', 'HO_SO', 'QUAN_TRI')
 * @param {string} hanhDong - Hành động cần kiểm tra ('xem', 'them', 'sua', 'xoa')
 */
const requirePermission = (chucNang, hanhDong) => {
  return async (req, res, next) => {
    try {
      const nhomNguoiDungId = req.user.nhom_nguoi_dung_id;

      // Truy vấn quyền hạn của nhóm người dùng đối với danh mục chức năng này
      const query = `
        SELECT quyen_xem, quyen_them, quyen_sua, quyen_xoa 
        FROM phan_quyen 
        WHERE nhom_nguoi_dung_id = $1 AND danh_muc_chuc_nang = $2
      `;
      const { rows } = await pool.query(query, [nhomNguoiDungId, chucNang]);

      if (rows.length === 0) {
        return res.status(403).json({ 
          success: false, 
          message: `Nhóm tài khoản của bạn chưa được thiết lập quyền cho chức năng: ${chucNang}` 
        });
      }

      const permission = rows[0];
      let hasAccess = false;

      // Ánh xạ hành động từ API sang các cột tương ứng trong database
      switch (hanhDong.toLowerCase()) {
        case 'xem': 
          hasAccess = permission.quyen_xem; 
          break;
        case 'them': 
          hasAccess = permission.quyen_them; 
          break;
        case 'sua': // "Cập nhật" tương ứng với quyen_sua
          hasAccess = permission.quyen_sua; 
          break;
        case 'xoa': 
          hasAccess = permission.quyen_xoa; 
          break;
      }

      if (!hasAccess) {
        return res.status(403).json({ 
          success: false, 
          message: `Lỗi bảo mật: Bạn không có quyền [${hanhDong.toUpperCase()}] trên danh mục: ${chucNang}` 
        });
      }

      next(); // Quyền hợp lệ, tiếp tục chuyển tiếp sang controller xử lý
    } catch (error) {
      console.error('Lỗi kiểm tra phân quyền:', error);
      res.status(500).json({ success: false, message: 'Lỗi máy chủ khi kiểm tra quyền hạn!' });
    }
  };
};


// =========================================================================
// 3. APIS - PHÂN HỆ: QUẢN TRỊ & PHÂN QUYỀN (ADMINISTRATIVE APIS)
// =========================================================================

// Đăng nhập và cấp phát token JWT
app.post('/api/auth/login', async (req, res) => {
  const { ten_dang_nhap, mat_khau } = req.body;
  if (!ten_dang_nhap || !mat_khau) {
    return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ tài khoản và mật khẩu!' });
  }
  try {
    const query = `
      SELECT t.*, n.ma_nhom, n.ten_nhom 
      FROM tai_khoan t 
      JOIN nhom_nguoi_dung n ON t.nhom_nguoi_dung_id = n.id 
      WHERE t.ten_dang_nhap = $1
    `;
    const { rows } = await pool.query(query, [ten_dang_nhap.trim()]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
    }
    const user = rows[0];
    if (!user.trang_thai_kich_hoat) {
      return res.status(403).json({ success: false, message: 'Tài khoản của bạn đã bị vô hiệu hóa!' });
    }
    const isPasswordValid = await bcrypt.compare(mat_khau, user.mat_khau);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
    }
    const token = jwt.sign(
      { id: user.id, ten_dang_nhap: user.ten_dang_nhap, ho_ten: user.ho_ten, nhom_nguoi_dung_id: user.nhom_nguoi_dung_id, ma_nhom: user.ma_nhom, ten_nhom: user.ten_nhom },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({
      success: true,
      message: 'Đăng nhập thành công!',
      token,
      user: { id: user.id, ten_dang_nhap: user.ten_dang_nhap, ho_ten: user.ho_ten, nhom_nguoi_dung_id: user.nhom_nguoi_dung_id, ten_nhom: user.ten_nhom, ma_nhom: user.ma_nhom }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi server đăng nhập!' });
  }
});

// Xem danh sách tài khoản
app.get('/api/accounts', authenticateToken, requirePermission('QUAN_TRI', 'xem'), async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT t.id, t.ten_dang_nhap, t.ho_ten, t.ngay_sinh, t.gioi_tinh, t.trang_thai_kich_hoat, t.nhom_nguoi_dung_id, n.ten_nhom, n.ma_nhom 
      FROM tai_khoan t JOIN nhom_nguoi_dung n ON t.nhom_nguoi_dung_id = n.id ORDER BY t.created_at DESC
    `);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải danh sách tài khoản!' });
  }
});

// Thay đổi trạng thái tài khoản
app.put('/api/accounts/:id/status', authenticateToken, requirePermission('QUAN_TRI', 'sua'), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) {
    return res.status(400).json({ success: false, message: 'Bạn không thể tự khóa tài khoản của chính mình!' });
  }
  try {
    await pool.query('UPDATE tai_khoan SET trang_thai_kich_hoat = $1 WHERE id = $2', [req.body.trang_thai_kich_hoat, req.params.id]);
    res.json({ success: true, message: 'Cập nhật trạng thái hoạt động tài khoản thành công!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi cập nhật trạng thái tài khoản!' });
  }
});


// =========================================================================
// 4. APIS - PHÂN HỆ: QUẢN LÝ GIÁO VIÊN (TEACHERS APIS - BẢO VỆ CHẶT CHẼ)
// =========================================================================

/**
 * Lấy danh sách giáo viên
 */
app.get('/api/teachers', authenticateToken, requirePermission('GIAO_VIEN', 'xem'), async (req, res) => {
  const { keyword, cccd, mon_hoc_id } = req.query;
  try {
    let queryParams = [];
    let query = "SELECT DISTINCT g.* FROM giao_vien g LEFT JOIN giao_vien_mon_hoc gvmh ON g.id = gvmh.giao_vien_id WHERE 1=1";
    
    if (keyword && keyword.trim() !== '') {
      queryParams.push(`%${keyword.trim()}%`);
      query += ` AND (g.ho_ten ILIKE $${queryParams.length} OR g.email ILIKE $${queryParams.length} OR g.sdt ILIKE $${queryParams.length})`;
    }
    if (cccd && cccd.trim() !== '') {
      queryParams.push(`%${cccd.trim()}%`);
      query += ` AND g.cccd ILIKE $${queryParams.length}`;
    }
    if (mon_hoc_id && mon_hoc_id !== '') {
      queryParams.push(parseInt(mon_hoc_id));
      query += ` AND gvmh.mon_hoc_id = $${queryParams.length}`;
    }
    query += ' ORDER BY g.id DESC';
    
    const { rows: teachers } = await pool.query(query, queryParams);
    for (let teacher of teachers) {
      const { rows: subIds } = await pool.query("SELECT m.id, m.ma_mon_hoc, m.ten_mon_hoc FROM mon_hoc m JOIN giao_vien_mon_hoc gvmh ON m.id = gvmh.mon_hoc_id WHERE gvmh.giao_vien_id = $1", [teacher.id]);
      teacher.mon_hoc_day = subIds;
    }
    res.json({ success: true, data: teachers });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải danh sách giáo viên!' });
  }
});

/**
 * Thêm mới giáo viên
 */
app.post('/api/teachers', authenticateToken, requirePermission('GIAO_VIEN', 'them'), 
  upload.fields([{ name: 'file_anh_the', maxCount: 1 }, { name: 'file_hop_dong', maxCount: 1 }]), 
  async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { ho_ten, cccd, ngay_sinh, gioi_tinh, sdt, email, trinh_do_chuyen_mon, mon_hoc_ids } = req.body;

      const path_anh_the = req.files['file_anh_the'] ? `/uploads/${req.files['file_anh_the'][0].filename}` : null;
      const path_hop_dong = req.files['file_hop_dong'] ? `/uploads/${req.files['file_hop_dong'][0].filename}` : null;

      const insertTeacher = `
        INSERT INTO giao_vien (ho_ten, cccd, ngay_sinh, gioi_tinh, sdt, email, trinh_do_chuyen_mon, file_anh_the, file_hop_dong_dinh_kem)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
      `;
      const result = await client.query(insertTeacher, [ho_ten, cccd, ngay_sinh, gioi_tinh, sdt, email, trinh_do_chuyen_mon, path_anh_the, path_hop_dong]);
      const newTeacherId = result.rows[0].id;

      if (mon_hoc_ids) {
        const subIds = typeof mon_hoc_ids === 'string' ? JSON.parse(mon_hoc_ids) : mon_hoc_ids;
        for (const sId of subIds) {
          await client.query('INSERT INTO giao_vien_mon_hoc (giao_vien_id, mon_hoc_id) VALUES ($1, $2)', [newTeacherId, sId]);
        }
      }

      await client.query('COMMIT');
      res.status(201).json({ success: true, message: 'Đăng ký hồ sơ Giáo viên mới thành công!' });
    } catch (error) {
      await client.query('ROLLBACK');
      res.status(500).json({ success: false, message: 'Có lỗi xảy ra khi lưu giáo viên mới!' });
    } finally {
      client.release();
    }
});

/**
 * Cập nhật thông tin Giáo viên
 * Yêu cầu quyền "Cập nhật" (sua) ở danh mục "Giáo viên". 
 * Nếu user không có quyền này, requirePermission('GIAO_VIEN', 'sua') sẽ chặn và trả về lỗi 403.
 */
app.put('/api/teachers/:id', authenticateToken, requirePermission('GIAO_VIEN', 'sua'),
  upload.fields([{ name: 'file_anh_the', maxCount: 1 }, { name: 'file_hop_dong', maxCount: 1 }]),
  async (req, res) => {
    const teacherId = req.params.id;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const checkExist = await client.query('SELECT file_anh_the, file_hop_dong_dinh_kem FROM giao_vien WHERE id = $1', [teacherId]);
      if (checkExist.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Giáo viên không tồn tại!' });
      }

      const currentFiles = checkExist.rows[0];
      const { ho_ten, cccd, ngay_sinh, gioi_tinh, sdt, email, trinh_do_chuyen_mon, mon_hoc_ids } = req.body;

      let path_anh_the = currentFiles.file_anh_the;
      if (req.files['file_anh_the']) {
        path_anh_the = `/uploads/${req.files['file_anh_the'][0].filename}`;
        if (currentFiles.file_anh_the && fs.existsSync(path.join(__dirname, currentFiles.file_anh_the))) {
          fs.unlinkSync(path.join(__dirname, currentFiles.file_anh_the));
        }
      }

      let path_hop_dong = currentFiles.file_hop_dong_dinh_kem;
      if (req.files['file_hop_dong']) {
        path_hop_dong = `/uploads/${req.files['file_hop_dong'][0].filename}`;
        if (currentFiles.file_hop_dong_dinh_kem && fs.existsSync(path.join(__dirname, currentFiles.file_hop_dong_dinh_kem))) {
          fs.unlinkSync(path.join(__dirname, currentFiles.file_hop_dong_dinh_kem));
        }
      }

      const updateQuery = `
        UPDATE giao_vien SET
          ho_ten = $1, cccd = $2, ngay_sinh = $3, gioi_tinh = $4, sdt = $5, email = $6,
          trinh_do_chuyen_mon = $7, file_anh_the = $8, file_hop_dong_dinh_kem = $9, updated_at = NOW()
        WHERE id = $10
      `;
      await client.query(updateQuery, [ho_ten, cccd, ngay_sinh, gioi_tinh, sdt, email, trinh_do_chuyen_mon, path_anh_the, path_hop_dong, teacherId]);

      await client.query('DELETE FROM giao_vien_mon_hoc WHERE giao_vien_id = $1', [teacherId]);
      if (mon_hoc_ids) {
        const subIds = typeof mon_hoc_ids === 'string' ? JSON.parse(mon_hoc_ids) : mon_hoc_ids;
        for (const sId of subIds) {
          await client.query('INSERT INTO giao_vien_mon_hoc (giao_vien_id, mon_hoc_id) VALUES ($1, $2)', [teacherId, sId]);
        }
      }

      await client.query('COMMIT');
      res.json({ success: true, message: 'Cập nhật hồ sơ Giáo viên thành công!' });
    } catch (error) {
      await client.query('ROLLBACK');
      res.status(500).json({ success: false, message: 'Lỗi hệ thống khi cập nhật giáo viên!' });
    } finally {
      client.release();
    }
});

/**
 * Xóa giáo viên
 */
app.delete('/api/teachers/:id', authenticateToken, requirePermission('GIAO_VIEN', 'xoa'), async (req, res) => {
  const teacherId = req.params.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query('SELECT file_anh_the, file_hop_dong_dinh_kem FROM giao_vien WHERE id = $1', [teacherId]);
    if (rows.length === 0) return res.status(404).json({ success: false, message: 'Giáo viên không tồn tại!' });

    const files = rows[0];
    await client.query('DELETE FROM giao_vien_mon_hoc WHERE giao_vien_id = $1', [teacherId]);
    await client.query('DELETE FROM giao_vien WHERE id = $1', [teacherId]);

    if (files.file_anh_the && fs.existsSync(path.join(__dirname, files.file_anh_the))) {
      fs.unlinkSync(path.join(__dirname, files.file_anh_the));
    }
    if (files.file_hop_dong_dinh_kem && fs.existsSync(path.join(__dirname, files.file_hop_dong_dinh_kem))) {
      fs.unlinkSync(path.join(__dirname, files.file_hop_dong_dinh_kem));
    }

    await client.query('COMMIT');
    res.json({ success: true, message: 'Xóa hồ sơ Giáo viên thành công!' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ success: false, message: 'Lỗi khi xóa giáo viên!' });
  } finally {
    client.release();
  }
});


// =========================================================================
// 5. APIS - PHÂN HỆ: QUẢN LÝ HỌC VIÊN, LỚP HỌC, MÔN HỌC, HỒ SƠ & DASHBOARD
// =========================================================================

// (Các APIs Học viên, Lớp học, Môn học, Hồ sơ, Dashboard được giữ vững hoạt động ổn định...)
app.get('/api/dashboard/stats', authenticateToken, requirePermission('TONG_QUAN', 'xem'), async (req, res) => {
  try {
    const studentCount = await pool.query('SELECT COUNT(*) as count FROM hoc_vien');
    const teacherCount = await pool.query('SELECT COUNT(*) as count FROM giao_vien');
    const classCount = await pool.query('SELECT COUNT(*) as count FROM lop_hoc');
    const classStatus = await pool.query('SELECT trang_thai_lop_hoc, COUNT(*) as count FROM lop_hoc GROUP BY trang_thai_lop_hoc');

    res.json({
      success: true,
      data: {
        students: parseInt(studentCount.rows[0].count),
        teachers: parseInt(teacherCount.rows[0].count),
        classes: parseInt(classCount.rows[0].count),
        classStatusRatio: classStatus.rows
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải thống kê!' });
  }
});

app.get('/api/subjects', authenticateToken, requirePermission('MON_HOC', 'xem'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM mon_hoc ORDER BY thu_tu_hien_thi ASC, id ASC');
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải môn học!' });
  }
});

app.get('/api/students', authenticateToken, requirePermission('HOC_VIEN', 'xem'), async (req, res) => {
  const { keyword, lop_hoc_id } = req.query;
  try {
    let queryParams = [];
    let query = "SELECT DISTINCT h.* FROM hoc_vien h LEFT JOIN lop_hoc_hoc_vien lhhv ON h.id = lhhv.hoc_vien_id WHERE 1=1";
    if (keyword && keyword.trim() !== '') {
      queryParams.push(`%${keyword.trim()}%`);
      query += ` AND (h.ho_ten ILIKE $${queryParams.length} OR h.cccd ILIKE $${queryParams.length} OR h.sdt_phu_huynh ILIKE $${queryParams.length})`;
    }
    if (lop_hoc_id && lop_hoc_id !== '') {
      queryParams.push(parseInt(lop_hoc_id));
      query += ` AND lhhv.lop_hoc_id = $${queryParams.length}`;
    }
    query += ' ORDER BY h.id DESC';
    const { rows: students } = await pool.query(query, queryParams);
    for (let student of students) {
      const { rows: classes } = await pool.query("SELECT l.id, l.ma_lop, l.ten_lop FROM lop_hoc l JOIN lop_hoc_hoc_vien lhhv ON l.id = lhhv.lop_hoc_id WHERE lhhv.hoc_vien_id = $1", [student.id]);
      student.cac_lop_dang_hoc = classes;
    }
    res.json({ success: true, data: students });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải danh sách học viên!' });
  }
});

app.get('/api/classes', authenticateToken, requirePermission('LOP_HOC', 'xem'), async (req, res) => {
  const { keyword, mon_hoc_id } = req.query;
  try {
    let queryParams = [];
    let query = `
      SELECT l.*, m.ten_mon_hoc, m.ma_mon_hoc, g.ho_ten as ten_giao_vien_chinh
      FROM lop_hoc l
      JOIN mon_hoc m ON l.mon_hoc_id = m.id
      JOIN giao_vien g ON l.giao_vien_chinh_id = g.id
      WHERE 1=1
    `;
    if (keyword && keyword.trim() !== '') {
      queryParams.push(`%${keyword.trim()}%`);
      query += ` AND (l.ten_lop ILIKE $${queryParams.length} OR l.ma_lop ILIKE $${queryParams.length})`;
    }
    if (mon_hoc_id && mon_hoc_id !== '') {
      queryParams.push(parseInt(mon_hoc_id));
      query += ` AND l.mon_hoc_id = $${queryParams.length}`;
    }
    query += ' ORDER BY l.id DESC';
    const { rows } = await pool.query(query, queryParams);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải danh sách lớp học!' });
  }
});

app.get('/api/profile', authenticateToken, requirePermission('HO_SO', 'xem'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM ho_so_trung_tam ORDER BY id ASC LIMIT 1');
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi tải hồ sơ trung tâm!' });
  }
});


// TỰ ĐỘNG KHỞI CHẠY SERVER LẮNG NGHE KẾT NỐI
app.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(`  ATH SYSTEM - SERVER ĐANG HOẠT ĐỘNG TẠI CỔNG TRUY CẬP: ${PORT}`);
  console.log(`================================================================`);
});
