INSERT INTO users (name, email, password, role, roll_number, department, cohort, phone)
SELECT 'Main Admin', 'admin@gmail.com', 'admin123', 'ADMIN', 'ADMIN001', 'Administration', '2022-2026', '9999999999'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@gmail.com');

UPDATE users SET roll_number='ADMIN001', department='Administration', cohort='2022-2026', phone='9999999999' WHERE email='admin@gmail.com';
UPDATE users SET roll_number='21BCE001', department='CSE', cohort='2021-2025', phone='9876543210' WHERE email='student@gmail.com';
UPDATE users SET roll_number='21BCE002', department='ECE', cohort='2021-2025', phone='9876543211' WHERE email='krishna@student.com';

INSERT INTO users (name, email, password, role, roll_number, department, cohort, phone)
SELECT 'Student 2', 'krishna@student.com', '1234', 'STUDENT', '21BCE002', 'ECE', '2021-2025', '9876543211'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'krishna@student.com');

INSERT INTO activities (name, type, role, duration, skills, start_date, end_date, slots)
SELECT 'Cricket Tournament', 'sports', 'Player', '2 days', 'Teamwork,Leadership,Discipline', '2026-04-10', '2026-04-12', 30
WHERE NOT EXISTS (SELECT 1 FROM activities WHERE name = 'Cricket Tournament');

INSERT INTO activities (name, type, role, duration, skills, start_date, end_date, slots)
SELECT 'Coding Club', 'club', 'Member', '1 year', 'Programming,Problem Solving,Teamwork', '2026-01-10', '2026-12-10', 60
WHERE NOT EXISTS (SELECT 1 FROM activities WHERE name = 'Coding Club');

INSERT INTO achievements (user_id, title, category, activity_category, description, date, certificate)
SELECT u.id, 'Cricket Tournament Winner', 'award', 'sports', 'Won the inter-college cricket tournament', '2026-04-12', 'certificate.pdf'
FROM users u
WHERE u.email = 'student@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM achievements WHERE title = 'Cricket Tournament Winner');

INSERT INTO achievements (user_id, title, category, activity_category, description, date, certificate)
SELECT u.id, 'Coding Club Recognition', 'recognition', 'technical', 'Recognized for strong contribution to coding club events', '2026-03-04', 'coding-club.pdf'
FROM users u
WHERE u.email = 'krishna@student.com'
  AND NOT EXISTS (SELECT 1 FROM achievements WHERE title = 'Coding Club Recognition');

INSERT INTO enrollments (user_id, activity_id, status, enrolled_date)
SELECT u.id, a.id, 'ENROLLED', CURRENT_DATE()
FROM users u
JOIN activities a ON a.name = 'Cricket Tournament'
WHERE u.email = 'student@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = u.id AND e.activity_id = a.id);

INSERT INTO categories (name)
SELECT 'Sports Competitions' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'Sports Competitions');
INSERT INTO categories (name)
SELECT 'Cultural Events' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'Cultural Events');
INSERT INTO categories (name)
SELECT 'NCC/NSS Participation' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'NCC/NSS Participation');
INSERT INTO categories (name)
SELECT 'Club Activities' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'Club Activities');
INSERT INTO categories (name)
SELECT 'Entrepreneurship' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'Entrepreneurship');
INSERT INTO categories (name)
SELECT 'Others' WHERE NOT EXISTS (SELECT 1 FROM categories WHERE name = 'Others');

INSERT INTO domains (name, category_id)
SELECT 'Competitive Sports', c.id FROM categories c
WHERE c.name = 'Sports Competitions'
  AND NOT EXISTS (SELECT 1 FROM domains WHERE name = 'Competitive Sports');

INSERT INTO domains (name, category_id)
SELECT 'Innovation Clubs', c.id FROM categories c
WHERE c.name = 'Club Activities'
  AND NOT EXISTS (SELECT 1 FROM domains WHERE name = 'Innovation Clubs');

INSERT INTO modules (name, domain_id, content)
SELECT 'Sports Leadership Basics', d.id, 'Introduction to leadership, teamwork, and tournament discipline.'
FROM domains d
WHERE d.name = 'Competitive Sports'
  AND NOT EXISTS (SELECT 1 FROM modules WHERE name = 'Sports Leadership Basics');

INSERT INTO modules (name, domain_id, content)
SELECT 'Club Event Planning', d.id, 'Learn planning, execution, and collaboration for club activities.'
FROM domains d
WHERE d.name = 'Innovation Clubs'
  AND NOT EXISTS (SELECT 1 FROM modules WHERE name = 'Club Event Planning');

INSERT INTO tests (module_id, question, option_a, option_b, option_c, option_d, correct_answer)
SELECT m.id, 'Which skill is most important in team sports?', 'Solo coding', 'Team coordination', 'Memorization', 'Silence', 'optionB'
FROM modules m
WHERE m.name = 'Sports Leadership Basics'
  AND NOT EXISTS (SELECT 1 FROM tests WHERE question = 'Which skill is most important in team sports?');

INSERT INTO tests (module_id, question, option_a, option_b, option_c, option_d, correct_answer)
SELECT m.id, 'What is the first step in planning a club event?', 'Ignore the audience', 'Define the objective', 'Skip scheduling', 'Close registrations', 'optionB'
FROM modules m
WHERE m.name = 'Club Event Planning'
  AND NOT EXISTS (SELECT 1 FROM tests WHERE question = 'What is the first step in planning a club event?');