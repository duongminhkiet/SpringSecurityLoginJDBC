# SpringSecurityLoginJDBC

Đây là ứng dụng DEMO cho Security trong Spring (SỬ DỤNG DB - JDBC) - dữ liệu test giống hệt với project: https://github.com/duongminhkiet/SpringSecurityLogin
Chạy lên vào: http://localhost:6062 Sử dụng các user test login vào trong CODE để đăng nhập theo các quyền, mỗi user mỗi quyền, các User có quyền ngang nhau chỉ vào được các URL của mình, không thể vào của user ngang cấp. Đối với user có quyền cao hơn như Admin thì sẽ vào được tất cả. Hoặc Manager sẽ vào được user Các tài khoản này chỉ được sử dụng trong code cứng, ko nằm trong DB.

Trong class WebSecurityConfig 
Hàm: configure 
Hàm: configure -> thay đổi từ hasAnyRole sang hasAuthority
